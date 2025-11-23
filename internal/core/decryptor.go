/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// decryptor.go: Chunked streaming decryption logic for go-fileencrypt
package core

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	crypto "github.com/gitrgoliveira/go-fileencrypt/internal/crypto"
)

// Decryptor handles chunked decryption of files and streams.
type Decryptor struct {
	keyBuf     *crypto.SecureBuffer
	chunkSize  int
	progress   func(float64)
	checksum   bool
	algorithm  Algorithm
	bufferPool *sync.Pool
}

func NewDecryptor(key []byte, opts ...Option) (*Decryptor, error) {
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
	return &Decryptor{
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

// DecryptFile performs chunked decryption of a file.
func (d *Decryptor) DecryptFile(ctx context.Context, srcPath, dstPath string) error {
	// Validate algorithm
	if !d.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", d.algorithm)
	}

	// Open source file (follows symlinks automatically)
	srcFile, err := os.Open(srcPath) // #nosec G304 -- File path provided by caller, library purpose is file decryption
	if err != nil {
		return crypto.WrapError("open source file", err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(dstPath) // #nosec G304 -- File path provided by caller, library purpose is file decryption
	if err != nil {
		return crypto.WrapError("create destination file", err)
	}
	defer dstFile.Close()

	// Create buffered reader and writer for improved I/O performance
	bufferedReader := bufio.NewReaderSize(srcFile, d.chunkSize)
	bufferedWriter := bufio.NewWriterSize(dstFile, d.chunkSize)
	defer func() {
		if flushErr := bufferedWriter.Flush(); flushErr != nil && err == nil {
			err = crypto.WrapError("flush buffer", flushErr)
		}
	}()

	// Delegate to DecryptStream (which will read the header and handle decryption)
	// Note: DecryptStream reads the file size from the header for progress reporting
	if err := d.DecryptStream(ctx, bufferedReader, bufferedWriter); err != nil {
		return err
	}

	// Verify checksum if requested
	if d.checksum {
		// Calculate checksum of decrypted file
		if _, err := CalculateChecksum(dstPath); err != nil {
			return crypto.WrapError("calculate checksum", err)
		}
	}

	return nil
}

// DecryptStream performs chunked decryption of a stream.
func (d *Decryptor) DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, sizeHint ...int64) error {
	// Validate algorithm
	if !d.algorithm.IsSupported() {
		return fmt.Errorf("unsupported algorithm: %s (only AES-256-GCM is currently supported)", d.algorithm)
	}

	// Validate key length
	key := d.keyBuf.Data()
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

	// Read and validate Magic Header
	magic := make([]byte, len(MagicBytes))
	if _, err := io.ReadFull(src, magic); err != nil {
		return crypto.WrapError("read magic bytes", err)
	}
	if string(magic) != MagicBytes {
		return fmt.Errorf("invalid file format: expected magic bytes %q, got %q", MagicBytes, magic)
	}

	version := make([]byte, 1)
	if _, err := io.ReadFull(src, version); err != nil {
		return crypto.WrapError("read version byte", err)
	}
	if version[0] != byte(Version) { // #nosec G602 -- version is size 1, ReadFull ensures it's filled
		return fmt.Errorf("unsupported file version: expected %d, got %d", Version, version[0])
	}

	// Read nonce and size from header
	baseNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(src, baseNonce); err != nil {
		return crypto.WrapError("read nonce", err)
	}

	sizeBytes := make([]byte, 8)
	if _, err := io.ReadFull(src, sizeBytes); err != nil {
		return crypto.WrapError("read size", err)
	}

	// Use file size as Additional Authenticated Data for GCM
	aad := sizeBytes

	// Get total size for progress reporting (from header or sizeHint)
	fileSizeUint64 := binary.BigEndian.Uint64(sizeBytes)
	var totalSize int64
	if fileSizeUint64 > 0 {
		totalSize = int64(fileSizeUint64) // #nosec G115 -- uint64 to int64 conversion safe for file sizes (validated in header)
	} else if len(sizeHint) > 0 {
		totalSize = sizeHint[0]
	}

	// Decrypt chunks
	var written int64
	var chunkCounter uint32

	for {
		if ctx.Err() != nil {
			return crypto.ErrContextCanceled
		}

		// Read chunk size
		chunkSizeBytes := make([]byte, 4)
		_, err := io.ReadFull(src, chunkSizeBytes)
		if err == io.EOF {
			break
		}
		if err != nil {
			return crypto.WrapError("read chunk size", err)
		}

		chunkSize := binary.BigEndian.Uint32(chunkSizeBytes)

		// Validate chunk size
		// #nosec G115 -- int to uint32 conversion safe (MaxChunkSize is 10MB)
		if chunkSize == 0 || chunkSize > uint32(MaxChunkSize+gcm.Overhead()) {
			return crypto.ErrChunkSize
		}

		// Read encrypted chunk
		ciphertext := make([]byte, chunkSize)
		if _, err := io.ReadFull(src, ciphertext); err != nil {
			return crypto.WrapError("read encrypted chunk", err)
		}

		// Create chunk-specific nonce
		nonce := make([]byte, NonceSize)
		copy(nonce, baseNonce)
		binary.BigEndian.PutUint32(nonce[8:], chunkCounter)
		chunkCounter++

		// Decrypt chunk (use file size as AAD for authentication)
		plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return crypto.WrapError("decrypt chunk (authentication failed)", err)
		}

		// Write plaintext
		if _, err := dst.Write(plaintext); err != nil {
			return crypto.WrapError("write plaintext chunk", err)
		}

		written += int64(len(plaintext))

		// Report progress (if sizeHint is provided)
		if d.progress != nil && totalSize > 0 {
			// Report as a fraction between 0.0 and 1.0 to match EncryptStream
			progress := float64(written) / float64(totalSize)
			d.progress(progress)
		}
	}

	// Report completion as fraction 1.0
	if d.progress != nil {
		d.progress(1.0)
	}

	return nil
}

// Destroy zeroes key material and unlocks memory
func (d *Decryptor) Destroy() {
	if d.keyBuf != nil {
		d.keyBuf.Destroy()
	}
}
