/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// Package fileencrypt provides secure, streaming file encryption and decryption
// for Go using AES-256-GCM authenticated encryption.
//
// This library is designed for encrypting files and streams of any size with
// strong cryptographic primitives, memory-safe key handling, and cross-platform
// compatibility. It uses chunked processing to handle large files without loading
// them entirely into memory.
//
// # Features
//
//   - Strong authenticated encryption with AES-256-GCM
//   - Streaming support for files of any size
//   - Cross-platform memory safety (mlock on Unix/macOS)
//   - Context support for cancellation and timeouts
//   - Progress tracking callbacks
//   - Modern key derivation: Argon2id (recommended) and PBKDF2-HMAC-SHA256
//   - Future-proof with reserved algorithm IDs for ChaCha20-Poly1305 and post-quantum crypto
//
// # Basic Usage
//
// Encrypt and decrypt a file with a random key:
//
//	import (
//	    "context"
//	    "crypto/rand"
//	    "github.com/gitrgoliveira/go-fileencrypt"
//	    "github.com/gitrgoliveira/go-fileencrypt/secure"
//	)
//
//	// Generate a 32-byte encryption key
//	key := make([]byte, 32)
//	rand.Read(key)
//	defer secure.Zero(key) // Always zero sensitive data
//
//	ctx := context.Background()
//
//	// Encrypt a file
//	err := fileencrypt.EncryptFile(ctx, "document.pdf", "document.pdf.enc", key)
//
//	// Decrypt the file
//	err = fileencrypt.DecryptFile(ctx, "document.pdf.enc", "document.pdf", key)
//
// # Password-Based Encryption
//
// Derive a key from a password using Argon2id (recommended for new applications):
//
//	password := []byte("your-secure-password")
//	salt, _ := fileencrypt.GenerateSalt(fileencrypt.DefaultSaltSize)
//
//	key, _ := fileencrypt.DeriveKeyArgon2(
//	    password, salt,
//	    fileencrypt.DefaultArgon2Time,      // 3 iterations
//	    fileencrypt.DefaultArgon2Memory,    // 64 MB
//	    fileencrypt.DefaultArgon2Threads,   // 4 threads
//	    fileencrypt.DefaultKeySize,         // 32 bytes
//	)
//	defer secure.Zero(key)
//
//	// Store the salt alongside your encrypted file - you'll need it for decryption!
//
// Or use PBKDF2 for compatibility with older systems:
//
//	key, _ := fileencrypt.DeriveKeyPBKDF2(
//	    password, salt,
//	    fileencrypt.DefaultPBKDF2Iterations, // 600,000 iterations
//	    fileencrypt.DefaultKeySize,          // 32 bytes
//	)
//
// # Stream Encryption
//
// Encrypt data from any io.Reader to any io.Writer:
//
//	var input io.Reader  // any reader
//	var output io.Writer // any writer
//
//	err := fileencrypt.EncryptStream(ctx, input, output, key)
//
// # Security Considerations
//
// Key Management:
//   - Always use crypto/rand for key generation
//   - Never hardcode keys in source code
//   - Always call secure.Zero(key) to clear keys from memory
//   - Store keys securely (HSM, KMS, encrypted storage)
//
// Passwords:
//   - Use strong passwords (12+ characters, mixed complexity)
//   - Generate unique, random salts (store with encrypted file)
//   - Prefer Argon2id over PBKDF2 for better GPU/ASIC attack resistance
//
// File Handling:
//   - Use secure file permissions (0600 for sensitive files)
//   - Validate decrypted data before use
//   - Handle authentication failures as potential tampering
//
// For complete documentation, examples, and security best practices,
// see: https://github.com/gitrgoliveira/go-fileencrypt
package fileencrypt

import (
	"context"
	"io"

	"github.com/gitrgoliveira/go-fileencrypt/internal/core"
	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// Option defines functional options for encryption/decryption (re-exported from internal/core).
type Option = core.Option

// WithChunkSize sets the chunk size for streaming operations (re-exported from internal/core).
var WithChunkSize = core.WithChunkSize

// WithProgress sets a progress callback (re-exported from internal/core).
var WithProgress = core.WithProgress

// Re-export checksum helpers from internal/core so callers can compute/verify checksums.
var CalculateChecksum = core.CalculateChecksum
var CalculateChecksumHex = core.CalculateChecksumHex
var VerifyChecksum = core.VerifyChecksum
var VerifyChecksumHex = core.VerifyChecksumHex

// WithAlgorithm sets the encryption algorithm (re-exported from internal/core).
var WithAlgorithm = core.WithAlgorithm

// EncryptFile encrypts a file.
func EncryptFile(ctx context.Context, srcPath, dstPath string, key []byte, opts ...Option) error {
	// Convert public options to internal core options
	coreOpts := make([]core.Option, len(opts))
	for i, opt := range opts {
		coreOpts[i] = core.Option(opt)
	}

	enc, err := core.NewEncryptor(key, coreOpts...)
	if err != nil {
		return err
	}
	return enc.EncryptFile(ctx, srcPath, dstPath)
}

// DecryptFile decrypts a file.
func DecryptFile(ctx context.Context, srcPath, dstPath string, key []byte, opts ...Option) error {
	coreOpts := make([]core.Option, len(opts))
	for i, opt := range opts {
		coreOpts[i] = core.Option(opt)
	}
	dec, err := core.NewDecryptor(key, coreOpts...)
	if err != nil {
		return err
	}
	return dec.DecryptFile(ctx, srcPath, dstPath)
}

// EncryptStream encrypts a stream.
func EncryptStream(ctx context.Context, src io.Reader, dst io.Writer, key []byte, opts ...Option) error {
	coreOpts := make([]core.Option, len(opts))
	for i, opt := range opts {
		coreOpts[i] = core.Option(opt)
	}
	enc, err := core.NewEncryptor(key, coreOpts...)
	if err != nil {
		return err
	}
	return enc.EncryptStream(ctx, src, dst)
}

// DecryptStream decrypts a stream.
func DecryptStream(ctx context.Context, src io.Reader, dst io.Writer, key []byte, opts ...Option) error {
	coreOpts := make([]core.Option, len(opts))
	for i, opt := range opts {
		coreOpts[i] = core.Option(opt)
	}
	dec, err := core.NewDecryptor(key, coreOpts...)
	if err != nil {
		return err
	}
	return dec.DecryptStream(ctx, src, dst)
}

// Re-export key derivation constants from internal/core
const (
	DefaultPBKDF2Iterations = core.DefaultPBKDF2Iterations
	DefaultSaltSize         = core.DefaultSaltSize
	DefaultKeySize          = core.DefaultKeySize
	DefaultArgon2Time       = core.DefaultArgon2Time
	DefaultArgon2Memory     = core.DefaultArgon2Memory
	DefaultArgon2Threads    = core.DefaultArgon2Threads
)

// ZeroKey securely zeroes a key slice. Always use defer ZeroKey(key) after key generation.
var ZeroKey = secure.Zero

// DeriveKeyPBKDF2 derives a key from a password using PBKDF2-HMAC-SHA256.
// For new applications, consider using DeriveKeyArgon2 instead (more resistant to GPU attacks).
// Re-exported from internal/core for public API.
func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return core.DeriveKeyPBKDF2(password, salt, iterations, keyLen)
}

// DeriveKeyArgon2 derives a key from a password using Argon2id.
// Argon2id is the recommended algorithm for password-based key derivation (2023).
// It provides better resistance to GPU/ASIC attacks compared to PBKDF2.
//
// OWASP 2023 recommended parameters for interactive logins:
//   - time: 3, memory: 65536 (64 MB), threads: 4, keyLen: 32
//
// Re-exported from internal/core for public API.
func DeriveKeyArgon2(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	return core.DeriveKeyArgon2(password, salt, time, memory, threads, keyLen)
}

// GenerateSalt generates a random salt of the specified size.
// Re-exported from internal/core for public API.
func GenerateSalt(size int) ([]byte, error) {
	return core.GenerateSalt(size)
}
