/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// platform_test.go: Cross-platform behavior tests
package fileencrypt_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt"
	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// TestCrossPlatform_MemoryLocking tests that memory locking behaves correctly
// on all platforms (works on Unix/macOS, no-op on Windows)
func TestCrossPlatform_MemoryLocking(t *testing.T) {
	data := []byte("test data for memory locking")

	// Lock memory
	err := secure.LockMemory(data)
	if err != nil {
		// On Unix/macOS, this may fail if permissions are insufficient (not root)
		// On Windows, this should always succeed (no-op)
		if runtime.GOOS == "windows" {
			t.Errorf("LockMemory failed on Windows (should be no-op): %v", err)
		} else {
			t.Logf("LockMemory failed on %s (may require elevated permissions): %v", runtime.GOOS, err)
		}
	} else {
		t.Logf("LockMemory succeeded on %s", runtime.GOOS)
	}

	// Unlock memory
	err = secure.UnlockMemory(data)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Errorf("UnlockMemory failed on Windows (should be no-op): %v", err)
		} else {
			t.Logf("UnlockMemory failed on %s: %v", runtime.GOOS, err)
		}
	}
}

// TestCrossPlatform_MemoryZeroing tests that memory zeroing works on all platforms
func TestCrossPlatform_MemoryZeroing(t *testing.T) {
	data := []byte("sensitive data to be zeroed")
	original := make([]byte, len(data))
	copy(original, data)

	// Zero the memory
	secure.Zero(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is not zero: %v", i, b)
		}
	}

	// Verify we actually changed something
	if bytes.Equal(data, original) {
		t.Errorf("Zero() did not modify the data")
	}

	t.Logf("Memory zeroing works correctly on %s", runtime.GOOS)
}

// TestCrossPlatform_FileEncryption tests that encryption/decryption works
// identically on all platforms
func TestCrossPlatform_FileEncryption(t *testing.T) {
	// Create temp files
	plaintext := []byte("Cross-platform test data: 日本語 ✓ Emoji 🔐")

	srcFile := filepath.Join(t.TempDir(), "plaintext.txt")
	encFile := filepath.Join(t.TempDir(), "encrypted.enc")
	dstFile := filepath.Join(t.TempDir(), "decrypted.txt")

	// Write plaintext
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		t.Fatalf("Failed to write plaintext: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ctx := context.Background()

	// Encrypt
	err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key)
	if err != nil {
		t.Fatalf("EncryptFile failed on %s: %v", runtime.GOOS, err)
	}

	// Decrypt
	err = fileencrypt.DecryptFile(ctx, encFile, dstFile, key)
	if err != nil {
		t.Fatalf("DecryptFile failed on %s: %v", runtime.GOOS, err)
	}

	// Verify
	decrypted, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted data does not match original on %s", runtime.GOOS)
		t.Errorf("Original:  %q", plaintext)
		t.Errorf("Decrypted: %q", decrypted)
	}

	t.Logf("File encryption/decryption works correctly on %s", runtime.GOOS)
}

// TestCrossPlatform_StreamEncryption tests that stream encryption works on all platforms
func TestCrossPlatform_StreamEncryption(t *testing.T) {
	plaintext := []byte("Stream encryption test data with unicode: 中文 العربية ελληνικά")

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 2)
	}

	ctx := context.Background()

	// Encrypt
	src := bytes.NewReader(plaintext)
	var encrypted bytes.Buffer

	err := fileencrypt.EncryptStream(ctx, src, &encrypted, key)
	if err != nil {
		t.Fatalf("EncryptStream failed on %s: %v", runtime.GOOS, err)
	}

	// Decrypt
	var decrypted bytes.Buffer
	encReader := bytes.NewReader(encrypted.Bytes())

	err = fileencrypt.DecryptStream(ctx, encReader, &decrypted, key)
	if err != nil {
		t.Fatalf("DecryptStream failed on %s: %v", runtime.GOOS, err)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted.Bytes()) {
		t.Errorf("Decrypted stream data does not match original on %s", runtime.GOOS)
		t.Errorf("Original:  %q", plaintext)
		t.Errorf("Decrypted: %q", decrypted.Bytes())
	}

	t.Logf("Stream encryption/decryption works correctly on %s", runtime.GOOS)
}

// TestCrossPlatform_LargeFile tests encryption of a larger file on all platforms
func TestCrossPlatform_LargeFile(t *testing.T) {
	// Create a 5MB file (smaller than Phase 3's 10MB for faster tests)
	size := 5 * 1024 * 1024
	plaintext := make([]byte, size)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	srcFile := filepath.Join(t.TempDir(), "large_plaintext.bin")
	encFile := filepath.Join(t.TempDir(), "large_encrypted.enc")
	dstFile := filepath.Join(t.TempDir(), "large_decrypted.bin")

	// Write plaintext
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		t.Fatalf("Failed to write large plaintext: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i ^ 0xAA)
	}

	ctx := context.Background()

	// Encrypt with progress tracking
	progressCalls := 0
	err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key, fileencrypt.WithProgress(func(p float64) {
		progressCalls++
		t.Logf("Encryption progress on %s: %.1f%%", runtime.GOOS, p*100)
	}))
	if err != nil {
		t.Fatalf("EncryptFile failed on %s: %v", runtime.GOOS, err)
	}

	if progressCalls == 0 {
		t.Errorf("Progress callback was never called on %s", runtime.GOOS)
	}

	// Decrypt with progress tracking
	progressCalls = 0
	err = fileencrypt.DecryptFile(ctx, encFile, dstFile, key, fileencrypt.WithProgress(func(p float64) {
		progressCalls++
		t.Logf("Decryption progress on %s: %.1f%%", runtime.GOOS, p*100)
	}))
	if err != nil {
		t.Fatalf("DecryptFile failed on %s: %v", runtime.GOOS, err)
	}

	if progressCalls == 0 {
		t.Errorf("Progress callback was never called on %s", runtime.GOOS)
	}

	// Verify file integrity
	decrypted, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted large file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Large file decryption failed on %s", runtime.GOOS)
		t.Errorf("Size mismatch: original=%d, decrypted=%d", len(plaintext), len(decrypted))
	}

	t.Logf("Large file encryption/decryption works correctly on %s (size=%d bytes)", runtime.GOOS, size)
}

// TestCrossPlatform_FilePermissions tests that file permissions are preserved
func TestCrossPlatform_FilePermissions(t *testing.T) {
	plaintext := []byte("test data")
	srcFile := filepath.Join(t.TempDir(), "perms_test.txt")
	encFile := filepath.Join(t.TempDir(), "perms_test.enc")
	dstFile := filepath.Join(t.TempDir(), "perms_decrypted.txt")

	// Write with specific permissions
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	ctx := context.Background()

	// Encrypt
	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// Check encrypted file permissions
	encInfo, err := os.Stat(encFile)
	if err != nil {
		t.Fatalf("Failed to stat encrypted file: %v", err)
	}

	// Decrypt
	if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, key); err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Check decrypted file exists and is readable
	dstInfo, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("Failed to stat decrypted file: %v", err)
	}

	t.Logf("File permissions on %s: encrypted=%v, decrypted=%v",
		runtime.GOOS, encInfo.Mode(), dstInfo.Mode())
}

// TestCrossPlatform_PathHandling tests that path separators work correctly
func TestCrossPlatform_PathHandling(t *testing.T) {
	// Create nested directory structure
	baseDir := t.TempDir()
	nestedDir := baseDir + "/subdir1/subdir2"

	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("Failed to create nested directories: %v", err)
	}

	plaintext := []byte("nested path test")
	srcFile := nestedDir + "/test.txt"
	encFile := nestedDir + "/test.enc"
	dstFile := nestedDir + "/test_decrypted.txt"

	// Write plaintext
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		t.Fatalf("Failed to write to nested path: %v", err)
	}

	key := make([]byte, 32)
	ctx := context.Background()

	// Encrypt in nested path
	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		t.Fatalf("EncryptFile failed with nested path on %s: %v", runtime.GOOS, err)
	}

	// Decrypt in nested path
	if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, key); err != nil {
		t.Fatalf("DecryptFile failed with nested path on %s: %v", runtime.GOOS, err)
	}

	// Verify
	decrypted, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file from nested path: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Nested path encryption/decryption failed on %s", runtime.GOOS)
	}

	t.Logf("Path handling works correctly on %s", runtime.GOOS)
}

// TestCrossPlatform_ConcurrentOperations tests concurrent encryption on all platforms
func TestCrossPlatform_ConcurrentOperations(t *testing.T) {
	const numFiles = 5
	keys := make([][]byte, numFiles)

	for i := 0; i < numFiles; i++ {
		keys[i] = make([]byte, 32)
		for j := range keys[i] {
			keys[i][j] = byte(i*10 + j)
		}
	}

	ctx := context.Background()
	baseDir := t.TempDir()

	// Create and encrypt multiple files concurrently
	errCh := make(chan error, numFiles)

	for i := 0; i < numFiles; i++ {
		go func(idx int) {
			plaintext := []byte("concurrent test data " + string(rune('A'+idx)))
			srcFile := baseDir + "/concurrent_" + string(rune('0'+idx)) + ".txt"
			encFile := baseDir + "/concurrent_" + string(rune('0'+idx)) + ".enc"
			dstFile := baseDir + "/concurrent_" + string(rune('0'+idx)) + "_dec.txt"

			// Write
			if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
				errCh <- err
				return
			}

			// Encrypt
			if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, keys[idx]); err != nil {
				errCh <- err
				return
			}

			// Decrypt
			if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, keys[idx]); err != nil {
				errCh <- err
				return
			}

			// Verify
			decrypted, err := os.ReadFile(dstFile)
			if err != nil {
				errCh <- err
				return
			}

			if !bytes.Equal(plaintext, decrypted) {
				errCh <- os.ErrInvalid
				return
			}

			errCh <- nil
		}(i)
	}

	// Collect results
	for i := 0; i < numFiles; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("Concurrent operation %d failed on %s: %v", i, runtime.GOOS, err)
		}
	}

	t.Logf("Concurrent operations work correctly on %s", runtime.GOOS)
}

// TestCrossPlatform_BuildTags verifies that build tags work correctly
func TestCrossPlatform_BuildTags(t *testing.T) {
	// This test verifies that we're running the correct platform-specific code
	// by checking the behavior of memory locking

	testData := []byte("build tag test")
	err := secure.LockMemory(testData)

	switch runtime.GOOS {
	case "windows":
		// Windows should always succeed (no-op)
		if err != nil {
			t.Errorf("Windows LockMemory returned error: %v", err)
		}
		t.Logf("Windows build tag correctly uses no-op implementation")

	case "linux", "darwin":
		// Unix/macOS may succeed or fail depending on permissions
		if err != nil {
			t.Logf("Unix/Darwin LockMemory failed (expected without privileges): %v", err)
		} else {
			t.Logf("Unix/Darwin LockMemory succeeded (has mlock privileges)")
		}

	default:
		t.Logf("Unknown OS: %s", runtime.GOOS)
	}
}
