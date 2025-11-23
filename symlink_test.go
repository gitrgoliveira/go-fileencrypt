/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package fileencrypt_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func TestEncryptFile_WithSymlink(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create a test file
	srcPath := filepath.Join(tmpDir, "original.txt")
	testData := []byte("Hello, symlink test!")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a symlink to the file
	symlinkPath := filepath.Join(tmpDir, "symlink.txt")
	if err := os.Symlink(srcPath, symlinkPath); err != nil {
		t.Skipf("Skipping test: cannot create symlink: %v", err)
	}

	// Encrypt using the symlink path
	encPath := filepath.Join(tmpDir, "encrypted.bin")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if err := fileencrypt.EncryptFile(context.Background(), symlinkPath, encPath, key); err != nil {
		t.Fatalf("EncryptFile with symlink failed: %v", err)
	}

	// Decrypt and verify
	decPath := filepath.Join(tmpDir, "decrypted.txt")
	if err := fileencrypt.DecryptFile(context.Background(), encPath, decPath, key); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Verify decrypted content
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Decrypted content mismatch. Got %q, want %q", decrypted, testData)
	}

	t.Logf("Successfully encrypted and decrypted file via symlink")
}

func TestEncryptFile_WithPipe(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a named pipe (FIFO)
	pipePath := filepath.Join(tmpDir, "test.pipe")
	if err := mkfifo(pipePath); err != nil {
		t.Skipf("Skipping test: cannot create named pipe: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testData := []byte("Hello from pipe!")
	encPath := filepath.Join(tmpDir, "encrypted.bin")

	// Write to pipe in goroutine
	done := make(chan error, 1)
	go func() {
		pipe, err := os.OpenFile(pipePath, os.O_WRONLY, 0)
		if err != nil {
			done <- err
			return
		}
		defer pipe.Close()
		_, err = pipe.Write(testData)
		done <- err
	}()

	// Encrypt from pipe (will write size 0 in header since pipes have no size)
	if err := fileencrypt.EncryptFile(context.Background(), pipePath, encPath, key); err != nil {
		t.Fatalf("EncryptFile with pipe failed: %v", err)
	}

	// Check writer goroutine completed
	if err := <-done; err != nil {
		t.Fatalf("Pipe writer failed: %v", err)
	}

	// Decrypt
	decPath := filepath.Join(tmpDir, "decrypted.txt")
	if err := fileencrypt.DecryptFile(context.Background(), encPath, decPath, key); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Verify decrypted content
	decrypted, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("Decrypted content mismatch. Got %q, want %q", decrypted, testData)
	}

	t.Logf("Successfully encrypted and decrypted from named pipe")
}
