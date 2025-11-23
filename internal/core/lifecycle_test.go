/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)
import "path/filepath"

func TestEncryptor_Destroy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	// Destroy should not panic
	enc.Destroy()

	// Multiple calls to Destroy should be safe
	enc.Destroy()
}

func TestDecryptor_Destroy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	// Destroy should not panic
	dec.Destroy()

	// Multiple calls to Destroy should be safe
	dec.Destroy()
}

func TestEncryptor_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.txt")
	dstPath := filepath.Join(tmpDir, "encrypted.enc")

	// Create a large file to ensure operation takes time
	largeData := make([]byte, 10*1024*1024) // 10MB
	if _, err := rand.Read(largeData); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}
	defer enc.Destroy()

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = enc.EncryptFile(ctx, srcPath, dstPath)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	t.Logf("Got expected cancellation error: %v", err)
}

func TestDecryptor_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.txt")
	encPath := filepath.Join(tmpDir, "encrypted.enc")
	dstPath := filepath.Join(tmpDir, "decrypted.txt")

	// Create and encrypt a large file
	largeData := make([]byte, 10*1024*1024) // 10MB
	if _, err := rand.Read(largeData); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, largeData, 0644); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	// Encrypt the file first
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := enc.EncryptFile(context.Background(), srcPath, encPath); err != nil {
		t.Fatal(err)
	}
	enc.Destroy()

	// Now try to decrypt with cancelled context
	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}
	defer dec.Destroy()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = dec.DecryptFile(ctx, encPath, dstPath)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}

	t.Logf("Got expected cancellation error: %v", err)
}

func TestEncryptStream_ProgressCallback(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	progressCalls := 0
	progressFunc := func(pct float64) {
		progressCalls++
		if pct < 0 || pct > 100 {
			t.Errorf("invalid progress percentage: %.2f", pct)
		}
	}

	enc, err := NewEncryptor(key, WithProgress(progressFunc))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()

	// Encrypt data that will trigger multiple progress updates
	data := make([]byte, 5*1024*1024) // 5MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	var encBuf bytes.Buffer
	if err := enc.EncryptStream(context.Background(), bytes.NewReader(data), &encBuf); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("progress callback was never called")
	}

	t.Logf("Progress callback invoked %d times", progressCalls)
}

func TestDecryptStream_ProgressCallback(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	// First encrypt some data
	data := make([]byte, 5*1024*1024) // 5MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	var encBuf bytes.Buffer
	if err := enc.EncryptStream(context.Background(), bytes.NewReader(data), &encBuf); err != nil {
		t.Fatal(err)
	}
	enc.Destroy()

	// Now decrypt with progress callback
	progressCalls := 0
	progressFunc := func(pct float64) {
		progressCalls++
		if pct < 0 || pct > 100 {
			t.Errorf("invalid progress percentage: %.2f", pct)
		}
	}

	dec, err := NewDecryptor(key, WithProgress(progressFunc))
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Destroy()

	var decBuf bytes.Buffer
	if err := dec.DecryptStream(context.Background(), &encBuf, &decBuf); err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("progress callback was never called")
	}

	t.Logf("Progress callback invoked %d times", progressCalls)
}

func TestEncryptFile_WithChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source.txt")
	dstPath := filepath.Join(tmpDir, "encrypted.enc")

	testData := []byte("Test data with checksum")
	if err := os.WriteFile(srcPath, testData, 0644); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	enc, err := NewEncryptor(key, WithChecksum(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()

	if err := enc.EncryptFile(context.Background(), srcPath, dstPath); err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Verify encrypted file exists
	if _, err := os.Stat(dstPath); os.IsNotExist(err) {
		t.Fatal("encrypted file was not created")
	}
}

func TestEncryptor_NilProgress(t *testing.T) {
	// Test that nil progress callback doesn't cause panic
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	// Create encryptor without progress callback (nil)
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Destroy()

	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := enc.EncryptStream(context.Background(), bytes.NewReader(data), &buf); err != nil {
		t.Fatalf("EncryptStream failed with nil progress: %v", err)
	}
}

func TestDecryptor_NilProgress(t *testing.T) {
	// Test that nil progress callback doesn't cause panic
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	defer secure.Zero(key)

	// Encrypt first
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	var encBuf bytes.Buffer
	if err := enc.EncryptStream(context.Background(), bytes.NewReader(data), &encBuf); err != nil {
		t.Fatal(err)
	}
	enc.Destroy()

	// Decrypt without progress callback (nil)
	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Destroy()

	var decBuf bytes.Buffer
	if err := dec.DecryptStream(context.Background(), &encBuf, &decBuf); err != nil {
		t.Fatalf("DecryptStream failed with nil progress: %v", err)
	}
}
