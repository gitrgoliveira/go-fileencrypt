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

	crypto "github.com/gitrgoliveira/go-fileencrypt/internal/crypto"
)

// Encryptor handles chunked encryption of files and streams.
type Encryptor struct {
	keyBuf     *crypto.SecureBuffer
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
	keyBuf, err := crypto.NewSecureBufferFromBytes(key)
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
	// Validate algorithm
	if !e.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", e.algorithm)
	}

	// Validate chunk size
	if e.chunkSize <= 0 || e.chunkSize > MaxChunkSize {
		return fmt.Errorf("invalid chunk size: must be between 1 and %d bytes", MaxChunkSize)
	}

	// Open source file (follows symlinks automatically)
	srcFile, err := os.Open(srcPath) // #nosec G304 -- File path provided by caller, library purpose is file encryption
	if err != nil {
		return crypto.WrapError("open source file", err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(dstPath) // #nosec G304 -- File path provided by caller, library purpose is file encryption
	if err != nil {
		return crypto.WrapError("create destination file", err)
	}
	defer dstFile.Close()

	// Create buffered reader and writer for improved I/O performance
	bufferedReader := bufio.NewReaderSize(srcFile, e.chunkSize)
	bufferedWriter := bufio.NewWriterSize(dstFile, e.chunkSize)
	defer func() {
		if flushErr := bufferedWriter.Flush(); flushErr != nil && err == nil {
			err = crypto.WrapError("flush buffer", flushErr)
		}
	}()

	// Get file size for progress reporting
	stat, err := srcFile.Stat()
	if err != nil {
		return crypto.WrapError("stat source file", err)
	}
	totalSize := stat.Size()

	// Delegate chunk encryption to EncryptStream, passing size as a hint
	if err := e.EncryptStream(ctx, bufferedReader, bufferedWriter, totalSize); err != nil {
		return err
	}

	// Calculate checksum if requested
	if e.checksum {
		if _, err := CalculateChecksum(dstPath); err != nil {
			return crypto.WrapError("calculate checksum", err)
		}
	}

	return nil
}

// EncryptStream performs chunked encryption of a stream.
// EncryptStream performs chunked encryption of a stream.
// If sizeHint > 0, it is used for progress reporting only.
func (e *Encryptor) EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, sizeHint ...int64) error {
	// Validate algorithm
	if !e.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", e.algorithm)
	}

	// Validate chunk size
	if e.chunkSize <= 0 || e.chunkSize > MaxChunkSize {
		return fmt.Errorf("invalid chunk size: must be between 1 and %d bytes", MaxChunkSize)
	}

	// Validate key length
	key := e.keyBuf.Data()
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: must be 32 bytes for AES-256")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return crypto.WrapError("create cipher", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return crypto.WrapError("create GCM", err)
	}

	// Generate base nonce
	baseNonce := make([]byte, NonceSize)
	if _, err := rand.Read(baseNonce); err != nil {
		return crypto.WrapError("generate nonce", err)
	}

	// Write Magic Header
	if _, err := dst.Write([]byte(MagicBytes)); err != nil {
		return crypto.WrapError("write magic bytes", err)
	}
	if _, err := dst.Write([]byte{Version}); err != nil {
		return crypto.WrapError("write version byte", err)
	}

	// Write nonce
	if _, err := dst.Write(baseNonce); err != nil {
		return crypto.WrapError("write nonce", err)
	}

	// Write file size to header
	var totalSize int64
	if len(sizeHint) > 0 {
		totalSize = sizeHint[0]
	}
	sizeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBytes, uint64(totalSize)) // #nosec G115 -- int64 to uint64 conversion safe for file sizes
	if _, err := dst.Write(sizeBytes); err != nil {
		return crypto.WrapError("write file size", err)
	}

	// Use file size as Additional Authenticated Data for GCM
	aad := sizeBytes

	// Encrypt chunks
	// Get buffer from pool
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
			return crypto.ErrContextCanceled
		}

		n, err := src.Read(buf)
		if n > 0 {
			// Create chunk-specific nonce
			nonce := make([]byte, NonceSize)
			copy(nonce, baseNonce)
			binary.BigEndian.PutUint32(nonce[8:], chunkCounter)
			chunkCounter++

			// Check for nonce overflow
			if chunkCounter == 0 {
				return fmt.Errorf("nonce overflow: stream too large for single encryption")
			}

			// Encrypt chunk (use file size as AAD for authentication)
			ciphertext := gcm.Seal(nil, nonce, buf[:n], aad) // #nosec G407 -- Nonce is randomly generated per file, not hardcoded

			// Write chunk size and encrypted data
			chunkSizeBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkSizeBytes, uint32(len(ciphertext))) // #nosec G115 -- len() result fits in uint32 (max chunk is 10MB)
			if _, err := dst.Write(chunkSizeBytes); err != nil {
				return crypto.WrapError("write chunk size", err)
			}

			if _, err := dst.Write(ciphertext); err != nil {
				return crypto.WrapError("write encrypted chunk", err)
			}

			written += int64(n)

			// Report progress (if sizeHint is provided)
			if e.progress != nil && totalSize > 0 && written >= progressNext {
				// Report as a fraction between 0.0 and 1.0
				progress := float64(written) / float64(totalSize)
				e.progress(progress)
				progressNext += progressStep
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return crypto.WrapError("read source stream", err)
		}
	}

	// Report 100% completion as fraction 1.0
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
