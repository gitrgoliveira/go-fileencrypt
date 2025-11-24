/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// encryptor.go: Chunked streaming encryption logic for go-fileencrypt
package core

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// Encryptor handles chunked encryption of files and streams.
type Encryptor struct {
	keyBuf     *secure.SecureBuffer
	chunkSize  int
	progress   func(float64)
	checksum   bool
	algorithm  Algorithm
	bufferPool *sync.Pool
	// startChunkCounter is a test hook to initialize the per-stream chunk counter.
	// It remains zero in normal use; tests may set it to trigger edge cases.
	startChunkCounter uint32
}

func NewEncryptor(key []byte, opts ...Option) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: must be 32 bytes for AES-256, got %d", len(key))
	}
	cfg := &Config{
		ChunkSize: DefaultChunkSize, // default 1MB
		Algorithm: AlgorithmAESGCM,  // default algorithm
	}
	for _, opt := range opts {
		opt(cfg)
	}
	// Validate chunk size only once, using WithChunkSize logic
	if cfg.ChunkSize < MinChunkSize || cfg.ChunkSize > MaxChunkSize {
		return nil, fmt.Errorf("invalid chunk size: must be between %d and %d bytes, got %d", MinChunkSize, MaxChunkSize, cfg.ChunkSize)
	}
	keyBuf, err := secure.NewSecureBufferFromBytes(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SecureBuffer for key: %w", err)
	}
	return &Encryptor{
		keyBuf:    keyBuf,
		chunkSize: cfg.ChunkSize,
		progress:  cfg.Progress,
		checksum:  cfg.Checksum,
		algorithm: cfg.Algorithm,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, cfg.ChunkSize)
				return &buf
			},
		},
	}, nil
}

// EncryptFile performs chunked encryption of a file.
func (e *Encryptor) EncryptFile(ctx context.Context, srcPath, dstPath string) error {
	if !e.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", e.algorithm)
	}

	if e.chunkSize <= 0 || e.chunkSize > MaxChunkSize {
		return fmt.Errorf("invalid chunk size: must be between 1 and %d bytes", MaxChunkSize)
	}

	srcFile, err := os.Open(srcPath) // #nosec G304 -- File path provided by caller, library purpose is file encryption
	if err != nil {
		return WrapError("open source file", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath) // #nosec G304 -- File path provided by caller, library purpose is file encryption
	if err != nil {
		return WrapError("create destination file", err)
	}
	defer dstFile.Close()

	bufferedReader := bufio.NewReaderSize(srcFile, e.chunkSize)
	bufferedWriter := bufio.NewWriterSize(dstFile, e.chunkSize)
	defer func() {
		if flushErr := bufferedWriter.Flush(); flushErr != nil && err == nil {
			err = WrapError("flush buffer", flushErr)
		}
	}()

	stat, err := srcFile.Stat()
	if err != nil {
		return WrapError("stat source file", err)
	}
	totalSize := stat.Size()

	if err := e.EncryptStream(ctx, bufferedReader, bufferedWriter, totalSize); err != nil {
		return err
	}

	if e.checksum {
		if _, err := CalculateChecksum(dstPath); err != nil {
			return WrapError("calculate checksum", err)
		}
	}

	return nil
}

// EncryptStream performs chunked encryption of a stream.
// If sizeHint > 0, it is used for progress reporting only.
func (e *Encryptor) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, sizeHint ...int64) error {
	if !e.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", e.algorithm)
	}

	if e.chunkSize <= 0 || e.chunkSize > MaxChunkSize {
		return fmt.Errorf("invalid chunk size: must be between 1 and %d bytes", MaxChunkSize)
	}

	key := e.keyBuf.Data()
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return WrapError("create cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return WrapError("create GCM", err)
	}

	baseNonce := make([]byte, NonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return WrapError("generate nonce", err)
	}

	if _, err := dst.Write([]byte(MagicBytes)); err != nil {
		return WrapError("write magic bytes", err)
	}
	if _, err := dst.Write([]byte{Version}); err != nil {
		return WrapError("write version byte", err)
	}

	if _, err := dst.Write(baseNonce); err != nil {
		return WrapError("write nonce", err)
	}

	var totalSize int64
	if len(sizeHint) > 0 {
		totalSize = sizeHint[0]
	}
	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(totalSize)) // #nosec G115 -- int64 to uint64 conversion safe for file sizes
	if _, err := dst.Write(sizeBytes); err != nil {
		return WrapError("write file size", err)
	}

	aad := sizeBytes

	bufPtr := e.bufferPool.Get().(*[]byte)
	defer e.bufferPool.Put(bufPtr)
	buf := *bufPtr

	var written int64
	chunkCounter := e.startChunkCounter
	progressNext := int64(0)
	var progressStep int64
	if totalSize > 0 {
		progressStep = totalSize / 5 // 20% intervals
	}

	for {
		if ctx.Err() != nil {
			return ErrContextCanceled
		}

		n, err := src.Read(buf)
		if n > 0 {
			nonce := make([]byte, NonceSize)
			copy(nonce, baseNonce)
			binary.BigEndian.PutUint32(nonce[8:], chunkCounter)
			chunkCounter++

			if chunkCounter == 0 {
				return fmt.Errorf("nonce overflow: stream too large for single encryption")
			}

			ciphertext := gcm.Seal(nil, nonce, buf[:n], aad) // #nosec G407 -- Nonce is randomly generated per file, not hardcoded

			chunkSizeBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkSizeBytes, uint32(len(ciphertext))) // #nosec G115 -- len() result fits in uint32 (max chunk is 10MB)
			if _, err := dst.Write(chunkSizeBytes); err != nil {
				return WrapError("write chunk size", err)
			}

			if _, err := dst.Write(ciphertext); err != nil {
				return WrapError("write encrypted chunk", err)
			}

			written += int64(n)

			if e.progress != nil && totalSize > 0 && written >= progressNext {
				progress := float64(written) / float64(totalSize)
				e.progress(progress)
				progressNext += progressStep
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return WrapError("read source stream", err)
		}
	}

	if e.progress != nil {
		e.progress(1.0)
	}

	return nil
}

// Destroy zeroes key material and unlocks memory
func (e *Encryptor) Destroy() {
	if e.keyBuf != nil {
		e.keyBuf.Destroy()
	}
}
