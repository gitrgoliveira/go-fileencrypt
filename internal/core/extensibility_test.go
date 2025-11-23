/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// extensibility_test.go: Extensibility and algorithm support tests
package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAlgorithmType(t *testing.T) {
	tests := []struct {
		name      string
		alg       Algorithm
		wantName  string
		supported bool
	}{
		{"AES-GCM", AlgorithmAESGCM, "AES-256-GCM", true},
		{"ChaCha20", AlgorithmChaCha20Poly1305, "ChaCha20-Poly1305", false},
		{"ML-KEM", AlgorithmMLKEMHybrid, "ML-KEM-Hybrid", false},
		{"Unknown", Algorithm(99), "Unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.wantName {
				t.Errorf("Algorithm.String() = %q, want %q", got, tt.wantName)
			}

			if got := tt.alg.IsSupported(); got != tt.supported {
				t.Errorf("Algorithm.IsSupported() = %v, want %v", got, tt.supported)
			}
		})
	}
}

func TestWithAlgorithm_AES256GCM(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.enc")
	decPath := filepath.Join(tmpDir, "test.dec")

	testData := []byte("test data for algorithm selection")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Encrypt with explicit AES-GCM algorithm
	enc, err := NewEncryptor(key, WithAlgorithm(AlgorithmAESGCM))
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	if err := enc.EncryptFile(ctx, srcPath, encPath); err != nil {
		t.Fatalf("EncryptFile with AES-GCM failed: %v", err)
	}

	// Decrypt with explicit AES-GCM algorithm
	dec, err := NewDecryptor(key, WithAlgorithm(AlgorithmAESGCM))
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	if err := dec.DecryptFile(ctx, encPath, decPath); err != nil {
		t.Fatalf("DecryptFile with AES-GCM failed: %v", err)
	}

	// Verify data
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Data mismatch. Got %q, want %q", decrypted, testData)
	}

	t.Log("Successfully encrypted/decrypted with explicit AES-256-GCM algorithm")
}

func TestWithAlgorithm_UnsupportedAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	key := make([]byte, 32)

	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.enc")

	testData := []byte("test data")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Try to encrypt with unsupported ChaCha20-Poly1305
	enc, err := NewEncryptor(key, WithAlgorithm(AlgorithmChaCha20Poly1305))
	if err != nil {
		// Should not fail at constructor, but at EncryptFile
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	err = enc.EncryptFile(ctx, srcPath, encPath)
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm, got nil")
	}

	if err.Error() != "unsupported algorithm: ChaCha20-Poly1305 (only AES-256-GCM is currently supported)" {
		t.Errorf("Unexpected error message: %v", err)
	}

	// Try to encrypt with unsupported ML-KEM
	enc2, err := NewEncryptor(key, WithAlgorithm(AlgorithmMLKEMHybrid))
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	err2 := enc2.EncryptFile(ctx, srcPath, encPath)
	if err2 == nil {
		t.Fatal("Expected error for unsupported algorithm, got nil")
	}

	if err2.Error() != "unsupported algorithm: ML-KEM-Hybrid (only AES-256-GCM is currently supported)" {
		t.Errorf("Unexpected error message: %v", err2)
	}

	t.Log("Unsupported algorithms correctly rejected")
}

func TestWithAlgorithm_Stream(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)

	// Test unsupported algorithm with stream API
	enc, err := NewEncryptor(key, WithAlgorithm(AlgorithmChaCha20Poly1305))
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	err = enc.EncryptStream(ctx, nil, nil)
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm in EncryptStream, got nil")
	}

	dec, err := NewDecryptor(key, WithAlgorithm(AlgorithmMLKEMHybrid))
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	err2 := dec.DecryptStream(ctx, nil, nil)
	if err2 == nil {
		t.Fatal("Expected error for unsupported algorithm in DecryptStream, got nil")
	}

	t.Log("Stream APIs correctly reject unsupported algorithms")
}

func TestAlgorithmReservedIDs(t *testing.T) {
	// Verify algorithm IDs are properly reserved
	if AlgorithmAESGCM != 1 {
		t.Errorf("AlgorithmAESGCM should be 1, got %d", AlgorithmAESGCM)
	}

	if AlgorithmChaCha20Poly1305 != 2 {
		t.Errorf("AlgorithmChaCha20Poly1305 should be 2, got %d", AlgorithmChaCha20Poly1305)
	}

	if AlgorithmMLKEMHybrid != 3 {
		t.Errorf("AlgorithmMLKEMHybrid should be 3, got %d", AlgorithmMLKEMHybrid)
	}

	t.Log("Algorithm IDs correctly reserved for future extensibility")
}

func TestDefaultAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	key := make([]byte, 32)

	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.enc")
	decPath := filepath.Join(tmpDir, "test.dec")

	testData := []byte("test with default algorithm")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Encrypt without specifying algorithm (should default to AES-GCM)
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	if err := enc.EncryptFile(ctx, srcPath, encPath); err != nil {
		t.Fatalf("EncryptFile with default algorithm failed: %v", err)
	}

	// Decrypt without specifying algorithm (should default to AES-GCM)
	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	if err := dec.DecryptFile(ctx, encPath, decPath); err != nil {
		t.Fatalf("DecryptFile with default algorithm failed: %v", err)
	}

	// Verify data
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Data mismatch. Got %q, want %q", decrypted, testData)
	}

	t.Log("Default algorithm (AES-256-GCM) works correctly")
}
