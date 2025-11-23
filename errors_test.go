/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// errors_test.go: Error handling tests for go-fileencrypt
package fileencrypt_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func TestEncryptFile_InvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	testData := []byte("test data")

	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Use wrong key length
	wrongKey := make([]byte, 16)

	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, wrongKey)
	if err == nil {
		t.Fatal("expected EncryptFile to fail with invalid key length")
	}
	t.Logf("Got expected error: %v", err)
}

func TestDecryptFile_WrongKey(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	decPath := filepath.Join(tmpDir, "test.txt.dec")
	testData := []byte("test data")

	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, key)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Decrypt with wrong key
	err = fileencrypt.DecryptFile(context.Background(), encPath, decPath, wrongKey)
	if err == nil {
		t.Fatal("expected DecryptFile to fail with wrong key")
	}
	t.Logf("Got expected error: %v", err)
}

func TestDecryptFile_CorruptedData(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	decPath := filepath.Join(tmpDir, "test.txt.dec")
	testData := []byte("test data")

	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, key)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Corrupt the encrypted file
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("failed to read encrypted file: %v", err)
	}
	encData[len(encData)-1] ^= 0xff // Flip last byte
	if err := os.WriteFile(encPath, encData, 0644); err != nil {
		t.Fatalf("failed to write corrupted file: %v", err)
	}

	err = fileencrypt.DecryptFile(context.Background(), encPath, decPath, key)
	if err == nil {
		t.Fatal("expected DecryptFile to fail with corrupted data")
	}
	t.Logf("Got expected error: %v", err)
}

func TestEncryptFile_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	testData := make([]byte, 10*1024*1024) // 10MB

	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key)
	if err == nil {
		t.Fatal("expected EncryptFile to fail with canceled context")
	}
	t.Logf("Got expected error: %v", err)
}

func TestEncryptFile_InvalidKey_Duplicate(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")

	testData := []byte("Test data")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Test with wrong key length (16 bytes instead of 32)
	wrongKey := make([]byte, 16)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, wrongKey)
	if err == nil {
		t.Fatal("expected error for invalid key length, got nil")
	}

	t.Logf("Got expected error: %v", err)
}

func TestDecryptFile_InvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "test.txt")
	encPath := filepath.Join(tmpDir, "test.txt.enc")
	decPath := filepath.Join(tmpDir, "test.txt.dec")

	testData := []byte("Test data for key validation")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encrypt with valid key
	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, key)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Try to decrypt with wrong key length
	wrongKey := make([]byte, 16)
	err = fileencrypt.DecryptFile(context.Background(), encPath, decPath, wrongKey)
	if err == nil {
		t.Fatal("expected error for invalid key length during decryption, got nil")
	}

	t.Logf("Got expected error: %v", err)
}

func TestEncryptFile_NonExistentSource(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "nonexistent.txt")
	encPath := filepath.Join(tmpDir, "output.enc")

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err := fileencrypt.EncryptFile(context.Background(), srcPath, encPath, key)
	if err == nil {
		t.Fatal("expected error for non-existent source file, got nil")
	}

	t.Logf("Got expected error: %v", err)
}

func TestDecryptFile_NonExistentSource(t *testing.T) {
	tmpDir := t.TempDir()
	encPath := filepath.Join(tmpDir, "nonexistent.enc")
	decPath := filepath.Join(tmpDir, "output.txt")

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	err := fileencrypt.DecryptFile(context.Background(), encPath, decPath, key)
	if err == nil {
		t.Fatal("expected error for non-existent encrypted file, got nil")
	}

	t.Logf("Got expected error: %v", err)
}
