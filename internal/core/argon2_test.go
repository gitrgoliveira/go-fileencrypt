/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func TestDeriveKeyArgon2_Success(t *testing.T) {
	password := []byte("test password")
	salt, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(salt)

	// Test with default OWASP 2023 parameters
	key, err := DeriveKeyArgon2(
		password,
		salt,
		DefaultArgon2Time,
		DefaultArgon2Memory,
		DefaultArgon2Threads,
		uint32(DefaultKeySize),
	)
	if err != nil {
		t.Fatalf("DeriveKeyArgon2 failed: %v", err)
	}
	defer secure.Zero(key)

	if len(key) != DefaultKeySize {
		t.Errorf("expected key length %d, got %d", DefaultKeySize, len(key))
	}

	t.Logf("Successfully derived %d-byte key from password using Argon2id", len(key))
}

func TestDeriveKeyArgon2_DifferentPasswords(t *testing.T) {
	salt, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(salt)

	key1, err := DeriveKeyArgon2([]byte("password1"), salt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key1)

	key2, err := DeriveKeyArgon2([]byte("password2"), salt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key2)

	if bytes.Equal(key1, key2) {
		t.Error("different passwords produced identical keys")
	}
}

func TestDeriveKeyArgon2_DifferentSalts(t *testing.T) {
	password := []byte("test password")

	salt1, _ := GenerateSalt(DefaultSaltSize)
	defer secure.Zero(salt1)
	salt2, _ := GenerateSalt(DefaultSaltSize)
	defer secure.Zero(salt2)

	key1, err := DeriveKeyArgon2(password, salt1, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key1)

	key2, err := DeriveKeyArgon2(password, salt2, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key2)

	if bytes.Equal(key1, key2) {
		t.Error("same password with different salts produced identical keys")
	}
}

func TestDeriveKeyArgon2_InvalidInputs(t *testing.T) {
	validSalt, _ := GenerateSalt(DefaultSaltSize)
	defer secure.Zero(validSalt)

	tests := []struct {
		name     string
		password []byte
		salt     []byte
		time     uint32
		memory   uint32
		threads  uint8
		keyLen   uint32
	}{
		{"empty password", []byte(""), validSalt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize)},
		{"short salt", []byte("password"), []byte("short"), DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize)},
		{"zero time", []byte("password"), validSalt, 0, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize)},
		{"low memory", []byte("password"), validSalt, DefaultArgon2Time, 1000, DefaultArgon2Threads, uint32(DefaultKeySize)},
		{"zero threads", []byte("password"), validSalt, DefaultArgon2Time, DefaultArgon2Memory, 0, uint32(DefaultKeySize)},
		{"zero keyLen", []byte("password"), validSalt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, 0},
		{"excessive keyLen", []byte("password"), validSalt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKeyArgon2(tt.password, tt.salt, tt.time, tt.memory, tt.threads, tt.keyLen)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestDeriveKeyArgon2_Deterministic(t *testing.T) {
	password := []byte("test password")
	salt, _ := GenerateSalt(DefaultSaltSize)
	defer secure.Zero(salt)

	// Derive key twice with same parameters
	key1, err := DeriveKeyArgon2(password, salt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key1)

	key2, err := DeriveKeyArgon2(password, salt, DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key2)

	if !bytes.Equal(key1, key2) {
		t.Error("same inputs produced different keys (should be deterministic)")
	}
}

func TestArgon2_EncryptionIntegration(t *testing.T) {
	password := []byte("test password")
	salt, err := GenerateSalt(DefaultSaltSize)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	defer secure.Zero(salt)

	// Use lighter parameters for faster tests (still secure)
	key, err := DeriveKeyArgon2(password, salt, 2, 32*1024, 2, uint32(DefaultKeySize))
	if err != nil {
		t.Fatalf("DeriveKeyArgon2 failed: %v", err)
	}
	defer secure.Zero(key)

	// Test encryption with derived key
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.enc")
	dstPath := filepath.Join(tmpDir, "decrypted.txt")

	plaintext := []byte("Test plaintext for Argon2")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	if err := enc.EncryptFile(context.Background(), srcPath, encPath); err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	if err := dec.DecryptFile(context.Background(), encPath, dstPath); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	decrypted, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted content doesn't match original")
	}

	t.Log("Successfully encrypted and decrypted with Argon2-derived key")
}

func TestArgon2_vs_PBKDF2_Comparison(t *testing.T) {
	password := []byte("test password")
	salt, _ := GenerateSalt(DefaultSaltSize)
	defer secure.Zero(salt)

	// Derive with both methods
	keyPBKDF2, err := DeriveKeyPBKDF2(password, salt, 480000, DefaultKeySize)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(keyPBKDF2)

	keyArgon2, err := DeriveKeyArgon2(password, salt, 2, 32*1024, 2, uint32(DefaultKeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(keyArgon2)

	// Keys should be different (different algorithms)
	if bytes.Equal(keyPBKDF2, keyArgon2) {
		t.Error("PBKDF2 and Argon2 produced identical keys (should be different)")
	}

	t.Log("Confirmed PBKDF2 and Argon2 produce different outputs as expected")
}
