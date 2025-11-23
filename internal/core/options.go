/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// options.go: Configuration options for go-fileencrypt
package core

import (
	"errors"
	"github.com/dustin/go-humanize"
	"math"
	"os"
)

// Algorithm represents a cryptographic algorithm
type Algorithm uint8

const (
	// AlgorithmAESGCM is AES-256-GCM (default, currently supported)
	AlgorithmAESGCM Algorithm = 1

	// AlgorithmChaCha20Poly1305 is ChaCha20-Poly1305 (reserved for future)
	AlgorithmChaCha20Poly1305 Algorithm = 2

	// AlgorithmMLKEMHybrid is ML-KEM hybrid post-quantum (reserved for future)
	AlgorithmMLKEMHybrid Algorithm = 3
)

// String returns the algorithm name
func (a Algorithm) String() string {
	switch a {
	case AlgorithmAESGCM:
		return "AES-256-GCM"
	case AlgorithmChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case AlgorithmMLKEMHybrid:
		return "ML-KEM-Hybrid"
	default:
		return "Unknown"
	}
}

// IsSupported returns true if the algorithm is currently implemented
func (a Algorithm) IsSupported() bool {
	return a == AlgorithmAESGCM
}

type Config struct {
	ChunkSize int
	Progress  func(float64)
	Checksum  bool
	Algorithm Algorithm
}

// Option defines functional options for encryption/decryption (chunk size, progress, checksum, algorithm, etc.)
type Option func(*Config)

const (
	MinChunkSize = 1 // Minimum valid chunk size
	// DefaultChunkSize is the default chunk size used by the library
	// for streaming operations. It is intentionally smaller than
	// `MaxChunkSize` (format limit) so the library uses sensible
	// default buffering without reaching the format's absolute max.
	DefaultChunkSize = 1 * 1024 * 1024 // 1MB default chunk size
)

// WithChunkSize sets the chunk size for streaming operations.
func WithChunkSize(size int) (Option, error) {
	// Check for environment variable override; default to the format-level MaxChunkSize
	maxChunkSize := MaxChunkSize
	if envLimit, exists := os.LookupEnv("FILEENCRYPT_CHUNKSIZE_LIMIT"); exists {
		if limit, err := humanize.ParseBytes(envLimit); err == nil && limit > 0 {
			// G115: Prevent integer overflow conversion uint64 -> int
			if limit > uint64(math.MaxInt) {
				return nil, errors.New("FILEENCRYPT_CHUNKSIZE_LIMIT too large: exceeds int max value")
			}
			maxChunkSize = int(limit)
		}
	}

	// Validate chunk size
	if size < MinChunkSize || size > maxChunkSize {
		return nil, errors.New("invalid chunk size: must be between 1 byte and the maximum limit")
	}

	return func(cfg *Config) {
		cfg.ChunkSize = size
	}, nil
}

// WithProgress sets a progress callback (called at every 20% interval).
//
// The callback receives a fraction between 0.0 and 1.0 (inclusive), where
// 0.0 means no progress and 1.0 means complete. Examples and documentation
// should use fractional progress (not percentages).
func WithProgress(cb func(float64)) Option {
	return func(cfg *Config) {
		cfg.Progress = cb
	}
}

// WithChecksum enables checksum calculation/verification.
func WithChecksum(enable bool) Option {
	return func(cfg *Config) {
		cfg.Checksum = enable
	}
}

// WithAlgorithm sets the encryption algorithm (default: AES-256-GCM).
// Currently only AlgorithmAESGCM is supported; others return an error.
func WithAlgorithm(alg Algorithm) Option {
	return func(cfg *Config) {
		cfg.Algorithm = alg
	}
}
