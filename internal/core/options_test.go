/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"os"
	"testing"
)

func TestWithProgress(t *testing.T) {
	called := false
	progressFunc := func(pct float64) {
		called = true
	}

	cfg := &Config{}
	opt := WithProgress(progressFunc)
	opt(cfg)

	if cfg.Progress == nil {
		t.Fatal("Progress callback not set")
	}

	// Test that the callback works
	cfg.Progress(50.0)
	if !called {
		t.Error("Progress callback was not called")
	}
}

func TestWithChecksum(t *testing.T) {
	cfg := &Config{
		Checksum: false,
	}

	opt := WithChecksum(true)
	opt(cfg)

	if !cfg.Checksum {
		t.Error("Checksum not enabled")
	}

	// Test disabling
	opt2 := WithChecksum(false)
	opt2(cfg)

	if cfg.Checksum {
		t.Error("Checksum not disabled")
	}
}

func TestWithChunkSize(t *testing.T) {
	tests := []struct {
		name      string
		chunkSize int
	}{
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt, err := WithChunkSize(tt.chunkSize)
			if err != nil {
				t.Fatalf("failed to create chunk size option: %v", err)
			}

			cfg := &Config{}
			opt(cfg)

			if cfg.ChunkSize != tt.chunkSize {
				t.Errorf("chunk size not set correctly: expected %d, got %d", tt.chunkSize, cfg.ChunkSize)
			}
		})
	}
}

func TestWithChunkSize_EnvOverride(t *testing.T) {
	tests := []struct {
		name          string
		envValue      string
		chunkSize     int
		expectedLimit int
		expectError   bool
	}{
		{"Valid 50MB override", "50MB", 1024 * 1024, 50 * 1024 * 1024, false},
		{"Invalid override", "invalid", 1024 * 1024, 10 * 1024 * 1024, true},
		{"Unset environment", "", 1024 * 1024, 10 * 1024 * 1024, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("FILEENCRYPT_CHUNKSIZE_LIMIT", tt.envValue)
				defer os.Unsetenv("FILEENCRYPT_CHUNKSIZE_LIMIT")
			}

			cfg := &Config{}
			topt, err := WithChunkSize(tt.chunkSize)
			if err != nil {
				t.Fatalf("WithChunkSize returned an error: %v", err)
			}
			topt(cfg)

			if cfg.ChunkSize > tt.expectedLimit {
				t.Errorf("ChunkSize exceeded limit: got %d, expected %d", cfg.ChunkSize, tt.expectedLimit)
			}
		})
	}
}

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		algo     Algorithm
		expected string
	}{
		{AlgorithmAESGCM, "AES-256-GCM"},
		{AlgorithmChaCha20Poly1305, "ChaCha20-Poly1305"},
		{AlgorithmMLKEMHybrid, "ML-KEM-Hybrid"},
		{Algorithm(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.algo.String()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAlgorithm_IsSupported(t *testing.T) {
	tests := []struct {
		algo      Algorithm
		supported bool
	}{
		{AlgorithmAESGCM, true},
		{AlgorithmChaCha20Poly1305, false},
		{AlgorithmMLKEMHybrid, false},
		{Algorithm(99), false},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			result := tt.algo.IsSupported()
			if result != tt.supported {
				t.Errorf("expected IsSupported() = %v, got %v", tt.supported, result)
			}
		})
	}
}

func TestWithAlgorithm(t *testing.T) {
	cfg := &Config{}
	opt := WithAlgorithm(AlgorithmChaCha20Poly1305)
	opt(cfg)

	if cfg.Algorithm != AlgorithmChaCha20Poly1305 {
		t.Errorf("Algorithm not set correctly: expected %v, got %v", AlgorithmChaCha20Poly1305, cfg.Algorithm)
	}
}
