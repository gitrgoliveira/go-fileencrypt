/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// fileencrypt.go: Public API for go-fileencrypt library
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
