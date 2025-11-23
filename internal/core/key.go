/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// key.go: Key derivation and management for go-fileencrypt
package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// DefaultPBKDF2Iterations is the default iteration count for PBKDF2
	DefaultPBKDF2Iterations = 600000 // OWASP recommendation (2023)

	// MinPBKDF2Iterations is the minimum safe iteration count
	MinPBKDF2Iterations = 210000 // OWASP minimum

	// DefaultSaltSize is the default salt size in bytes
	DefaultSaltSize = 32

	// DefaultKeySize is the default derived key size (32 bytes for AES-256)
	DefaultKeySize = 32

	// Argon2id parameters (OWASP 2023 recommendations for interactive logins)
	// See: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

	// DefaultArgon2Time is the number of iterations (time cost)
	DefaultArgon2Time = 3

	// DefaultArgon2Memory is the memory cost in KiB (64 MB)
	DefaultArgon2Memory = 64 * 1024

	// DefaultArgon2Threads is the parallelism factor
	DefaultArgon2Threads = 4

	// MinArgon2Memory is the minimum memory cost (19 MB per OWASP minimum)
	MinArgon2Memory = 19 * 1024
)

// DeriveKeyPBKDF2 derives a key from a password using PBKDF2-HMAC-SHA256.
// Returns the derived key. The caller must securely zero the key after use.
//
// Parameters:
//   - password: The password bytes (will not be modified)
//   - salt: The salt bytes (must be at least 16 bytes, recommended 32 bytes)
//   - iterations: Number of iterations (must be >= MinPBKDF2Iterations)
//   - keyLen: Length of the derived key in bytes (typically 32 for AES-256)
//
// Example:
//
//	salt := make([]byte, DefaultSaltSize)
//	if _, err := rand.Read(salt); err != nil {
//	    return err
//	}
//	key, err := DeriveKeyPBKDF2([]byte("password"), salt, DefaultPBKDF2Iterations, DefaultKeySize)
//	if err != nil {
//	    return err
//	}
//	defer secure.Zero(key)
func DeriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes, got %d", len(salt))
	}

	if iterations < MinPBKDF2Iterations {
		return nil, fmt.Errorf("iterations must be at least %d, got %d", MinPBKDF2Iterations, iterations)
	}

	if keyLen <= 0 || keyLen > 128 {
		return nil, fmt.Errorf("keyLen must be between 1 and 128 bytes, got %d", keyLen)
	}

	// Use golang.org/x/crypto/pbkdf2 for key derivation
	key := pbkdf2.Key(password, salt, iterations, keyLen, sha256.New)
	return key, nil
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt(size int) ([]byte, error) {
	if size < 16 {
		return nil, fmt.Errorf("salt size must be at least 16 bytes, got %d", size)
	}

	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	return salt, nil
}

// DeriveKeyArgon2 derives a key from a password using Argon2id.
// Argon2id is the recommended password hashing algorithm as of 2023 (winner of Password Hashing Competition).
// It provides better resistance to GPU/ASIC attacks compared to PBKDF2.
//
// Parameters:
//   - password: The password bytes (will not be modified)
//   - salt: The salt bytes (must be at least 16 bytes, recommended 32 bytes)
//   - time: Time cost (number of iterations), minimum 1, recommended 3+
//   - memory: Memory cost in KiB (minimum 19456 = 19 MB, recommended 65536 = 64 MB)
//   - threads: Parallelism factor (recommended: number of CPU cores, typically 4)
//   - keyLen: Length of the derived key in bytes (typically 32 for AES-256)
//
// OWASP 2023 Recommendations:
//   - Interactive logins: memory=64MB, time=3, threads=4
//   - Background operations: memory=256MB, time=4, threads=4
//   - Minimum acceptable: memory=19MB, time=2, threads=1
//
// Example:
//
//	salt, _ := GenerateSalt(DefaultSaltSize)
//	key, err := DeriveKeyArgon2(
//	    []byte("password"),
//	    salt,
//	    DefaultArgon2Time,     // 3 iterations
//	    DefaultArgon2Memory,   // 64 MB
//	    DefaultArgon2Threads,  // 4 threads
//	    DefaultKeySize,        // 32 bytes
//	)
//	if err != nil {
//	    return err
//	}
//	defer secure.Zero(key)
func DeriveKeyArgon2(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes, got %d", len(salt))
	}

	if time < 1 {
		return nil, fmt.Errorf("time cost must be at least 1, got %d", time)
	}

	if memory < MinArgon2Memory {
		return nil, fmt.Errorf("memory cost must be at least %d KiB, got %d", MinArgon2Memory, memory)
	}

	if threads < 1 {
		return nil, fmt.Errorf("threads must be at least 1, got %d", threads)
	}

	if keyLen == 0 || keyLen > 128 {
		return nil, fmt.Errorf("keyLen must be between 1 and 128 bytes, got %d", keyLen)
	}

	// Use Argon2id (hybrid version combining Argon2i and Argon2d)
	// Provides resistance to both side-channel and GPU attacks
	key := argon2.IDKey(password, salt, time, memory, threads, keyLen)
	return key, nil
}
