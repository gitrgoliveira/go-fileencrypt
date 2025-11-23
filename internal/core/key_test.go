/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// key_test.go: Tests for key derivation and management
package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func TestDeriveKeyPBKDF2_Success(t *testing.T) {
	password := []byte("test-password-123")
	salt := make([]byte, DefaultSaltSize)
	copy(salt, []byte("test-salt-value-012345678901234567890"))

	key, err := DeriveKeyPBKDF2(password, salt, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key)

	if len(key) != DefaultKeySize {
		t.Errorf("Expected key length %d, got %d", DefaultKeySize, len(key))
	}

	// Verify deterministic output (same password/salt/iterations produces same key)
	key2, err := DeriveKeyPBKDF2(password, salt, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 second call failed: %v", err)
	}
	defer secure.Zero(key2)

	if !bytes.Equal(key, key2) {
		t.Error("PBKDF2 is not deterministic")
	}

	t.Logf("Successfully derived %d-byte key from password", len(key))
}

func TestDeriveKeyPBKDF2_DifferentPasswords(t *testing.T) {
	salt := make([]byte, DefaultSaltSize)
	copy(salt, []byte("test-salt-value-012345678901234567890"))

	key1, err := DeriveKeyPBKDF2([]byte("password1"), salt, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key1)

	key2, err := DeriveKeyPBKDF2([]byte("password2"), salt, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key2)

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords produced the same key")
	}
}

func TestDeriveKeyPBKDF2_DifferentSalts(t *testing.T) {
	password := []byte("test-password")

	salt1 := make([]byte, DefaultSaltSize)
	copy(salt1, []byte("salt1-value-0123456789012345678901234"))

	salt2 := make([]byte, DefaultSaltSize)
	copy(salt2, []byte("salt2-value-0123456789012345678901234"))

	key1, err := DeriveKeyPBKDF2(password, salt1, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key1)

	key2, err := DeriveKeyPBKDF2(password, salt2, DefaultPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key2)

	if bytes.Equal(key1, key2) {
		t.Error("Different salts produced the same key")
	}
}

func TestDeriveKeyPBKDF2_InvalidInputs(t *testing.T) {
	validPassword := []byte("password")
	validSalt := make([]byte, DefaultSaltSize)

	tests := []struct {
		name       string
		password   []byte
		salt       []byte
		iterations int
		keyLen     int
		wantErr    bool
	}{
		{"empty password", []byte{}, validSalt, DefaultPBKDF2Iterations, DefaultKeySize, true},
		{"short salt", validPassword, []byte("short"), DefaultPBKDF2Iterations, DefaultKeySize, true},
		{"too few iterations", validPassword, validSalt, 1000, DefaultKeySize, true},
		{"zero keyLen", validPassword, validSalt, DefaultPBKDF2Iterations, 0, true},
		{"excessive keyLen", validPassword, validSalt, DefaultPBKDF2Iterations, 256, true},
		{"valid minimum", validPassword, make([]byte, 16), MinPBKDF2Iterations, 16, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := DeriveKeyPBKDF2(tt.password, tt.salt, tt.iterations, tt.keyLen)
			if key != nil {
				defer secure.Zero(key)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveKeyPBKDF2() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && len(key) != tt.keyLen {
				t.Errorf("Expected key length %d, got %d", tt.keyLen, len(key))
			}
		})
	}
}

func TestGenerateSalt_Success(t *testing.T) {
	salt, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt) != DefaultSaltSize {
		t.Errorf("Expected salt length %d, got %d", DefaultSaltSize, len(salt))
	}

	// Verify randomness (two salts should not be equal)
	salt2, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatalf("GenerateSalt second call failed: %v", err)
	}

	if bytes.Equal(salt, salt2) {
		t.Error("Two generated salts are identical (not random)")
	}

	// Verify salt is not all zeros
	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Generated salt is all zeros")
	}

	t.Logf("Successfully generated %d-byte random salt", len(salt))
}

func TestGenerateSalt_InvalidSize(t *testing.T) {
	_, err := GenerateSalt(8) // Too small
	if err == nil {
		t.Error("Expected error for salt size < 16 bytes")
	}
}

func TestPBKDF2_EncryptionIntegration(t *testing.T) {
	// Test that PBKDF2-derived keys work with encryption/decryption
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Derive key from password
	password := []byte("secure-password-123")
	salt, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	key, err := DeriveKeyPBKDF2(password, salt, MinPBKDF2Iterations, DefaultKeySize)
	if err != nil {
		t.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
	}
	defer secure.Zero(key)

	// Encrypt test data
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	decPath := filepath.Join(tmpDir, "test.txt.dec")

	testData := []byte("test data encrypted with PBKDF2-derived key")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Encrypt with PBKDF2-derived key
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	if err := enc.EncryptFile(ctx, srcPath, encPath); err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Decrypt with same PBKDF2-derived key
	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	if err := dec.DecryptFile(ctx, encPath, decPath); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Verify decrypted data matches original
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data mismatch. Got %q, want %q", decrypted, testData)
	}

	t.Log("Successfully encrypted and decrypted with PBKDF2-derived key")
}
