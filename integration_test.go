/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package fileencrypt_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt"
	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func TestIntegration_FullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Generate key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer secure.Zero(key)

	// Create test file
	srcPath := filepath.Join(tmpDir, "test.txt")
	plaintext := []byte("Integration test data for full workflow")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Encrypt
	encPath := filepath.Join(tmpDir, "test.enc")
	if err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decPath := filepath.Join(tmpDir, "test.dec")
	if err := fileencrypt.DecryptFile(ctx, encPath, decPath, key); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted content does not match original")
	}

	t.Log("Full workflow test passed: generate key → encrypt → decrypt → verify")
}

func TestIntegration_PasswordBasedWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	password := []byte("test-password-123")
	salt, err := fileencrypt.GenerateSalt(fileencrypt.DefaultSaltSize)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Derive key
	key, err := fileencrypt.DeriveKeyPBKDF2(password, salt, fileencrypt.DefaultPBKDF2Iterations, fileencrypt.DefaultKeySize)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	defer secure.Zero(key)

	// Create test file
	srcPath := filepath.Join(tmpDir, "test.txt")
	plaintext := []byte("Password-based encryption test")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Encrypt
	encPath := filepath.Join(tmpDir, "test.enc")
	if err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Re-derive key (simulating decryption later)
	key2, err := fileencrypt.DeriveKeyPBKDF2(password, salt, fileencrypt.DefaultPBKDF2Iterations, fileencrypt.DefaultKeySize)
	if err != nil {
		t.Fatalf("Failed to re-derive key: %v", err)
	}
	defer secure.Zero(key2)

	// Decrypt
	decPath := filepath.Join(tmpDir, "test.dec")
	if err := fileencrypt.DecryptFile(ctx, encPath, decPath, key2); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted content does not match original")
	}

	t.Log("Password-based workflow test passed: derive key → encrypt → re-derive → decrypt")
}

func TestIntegration_StreamWorkflow(t *testing.T) {
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer secure.Zero(key)

	plaintext := []byte("Stream encryption test data")

	// Encrypt stream
	var encBuf bytes.Buffer
	if err := fileencrypt.EncryptStream(ctx, bytes.NewReader(plaintext), &encBuf, key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt stream
	var decBuf bytes.Buffer
	if err := fileencrypt.DecryptStream(ctx, bytes.NewReader(encBuf.Bytes()), &decBuf, key); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, decBuf.Bytes()) {
		t.Error("Decrypted content does not match original")
	}

	t.Log("Stream workflow test passed: encrypt stream → decrypt stream → compare")
}

func TestIntegration_LargeFileWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tmpDir := t.TempDir()
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer secure.Zero(key)

	// Create large test file (10MB)
	srcPath := filepath.Join(tmpDir, "large.bin")
	plaintext := make([]byte, 10*1024*1024)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Track progress
	progressCount := 0
	progressCallback := func(progress float64) {
		progressCount++
		t.Logf("Progress: %.1f%%", progress)
	}

	// Encrypt with progress
	encPath := filepath.Join(tmpDir, "large.enc")
	if err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key, fileencrypt.WithProgress(progressCallback)); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if progressCount == 0 {
		t.Error("Progress callback was not called during encryption")
	}

	// Decrypt
	decPath := filepath.Join(tmpDir, "large.dec")
	if err := fileencrypt.DecryptFile(ctx, encPath, decPath, key); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify sizes match
	srcInfo, _ := os.Stat(srcPath)
	decInfo, _ := os.Stat(decPath)
	if srcInfo.Size() != decInfo.Size() {
		t.Errorf("File sizes don't match: original=%d, decrypted=%d", srcInfo.Size(), decInfo.Size())
	}

	// Verify content matches via SHA-256 checksum (safer for large files)
	srcFile, err := os.Open(srcPath)
	if err != nil {
		t.Fatalf("Failed to open source file for checksum: %v", err)
	}
	defer srcFile.Close()

	decFile, err := os.Open(decPath)
	if err != nil {
		t.Fatalf("Failed to open decrypted file for checksum: %v", err)
	}
	defer decFile.Close()

	hSrc := sha256.New()
	if _, err := io.Copy(hSrc, srcFile); err != nil {
		t.Fatalf("Failed to hash source file: %v", err)
	}

	hDec := sha256.New()
	if _, err := io.Copy(hDec, decFile); err != nil {
		t.Fatalf("Failed to hash decrypted file: %v", err)
	}

	sumSrc := hSrc.Sum(nil)
	sumDec := hDec.Sum(nil)
	if !bytes.Equal(sumSrc, sumDec) {
		t.Errorf("SHA-256 checksum mismatch for large file: %x != %x", sumSrc, sumDec)
	}

	t.Logf("Large file workflow test passed: 10MB+ file with progress tracking (progress callbacks: %d)", progressCount)
}

func TestIntegration_MultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer secure.Zero(key)

	// Encrypt multiple files and collect nonces
	nonces := make(map[string]bool)
	fileCount := 10

	for i := 0; i < fileCount; i++ {
		// Create unique file
		srcPath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+".txt")
		plaintext := []byte("Test data " + string(rune('0'+i)))
		if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
			t.Fatalf("Failed to create test file %d: %v", i, err)
		}

		// Encrypt
		encPath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+".enc")
		if err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key); err != nil {
			t.Fatalf("Encryption failed for file %d: %v", i, err)
		}

		// Read nonce from encrypted file
		encData, err := os.ReadFile(encPath)
		if err != nil {
			t.Fatalf("Failed to read encrypted file %d: %v", i, err)
		}
		if len(encData) < 12 {
			t.Fatalf("Encrypted file %d too small", i)
		}
		nonce := hex.EncodeToString(encData[:12])

		// Check for nonce collision
		if nonces[nonce] {
			t.Fatalf("Nonce collision detected at file %d: %s", i, nonce)
		}
		nonces[nonce] = true

		// Decrypt and verify
		decPath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+".dec")
		if err := fileencrypt.DecryptFile(ctx, encPath, decPath, key); err != nil {
			t.Fatalf("Decryption failed for file %d: %v", i, err)
		}

		decrypted, err := os.ReadFile(decPath)
		if err != nil {
			t.Fatalf("Failed to read decrypted file %d: %v", i, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("File %d: decrypted content does not match original", i)
		}
	}

	t.Logf("Multiple files test passed: %d files encrypted with unique nonces, all decrypted correctly", fileCount)
}

func TestIntegration_ErrorRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	defer secure.Zero(key)

	// Create and encrypt a valid file
	srcPath := filepath.Join(tmpDir, "test.txt")
	plaintext := []byte("Test data for corruption")
	if err := os.WriteFile(srcPath, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	encPath := filepath.Join(tmpDir, "test.enc")
	if err := fileencrypt.EncryptFile(ctx, srcPath, encPath, key); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Corrupt the encrypted file (flip a bit in actual encrypted chunk data, not header)
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Flip a bit in the encrypted chunk data (after header which is 20 bytes + 4 byte chunk size)
	if len(encData) > 30 {
		encData[30] ^= 0xFF
		if err := os.WriteFile(encPath, encData, 0644); err != nil {
			t.Fatalf("Failed to write corrupted file: %v", err)
		}
	}

	// Try to decrypt corrupted file - should fail gracefully with authentication error
	decPath := filepath.Join(tmpDir, "test.dec")
	err = fileencrypt.DecryptFile(ctx, encPath, decPath, key)
	if err == nil {
		t.Fatal("Expected error for corrupted file, got nil")
	}

	t.Logf("Error recovery test passed: corrupted file → graceful error: %v", err)
}
