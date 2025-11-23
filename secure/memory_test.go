/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// memory_test.go: Memory utility tests for go-fileencrypt
package secure_test

import (
	"bytes"
	"crypto/rand"
	"runtime"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func TestLockUnlockMemory(t *testing.T) {
	// Create test buffer
	buf := make([]byte, 4096)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}

	// Lock memory (may be no-op on Windows)
	err := secure.LockMemory(buf)
	if err != nil {
		// On some systems, mlock may fail due to insufficient permissions
		// or resource limits. Log but don't fail the test.
		t.Logf("LockMemory failed (may be expected on some systems): %v", err)
	}

	// Unlock memory
	err = secure.UnlockMemory(buf)
	if err != nil {
		t.Logf("UnlockMemory failed: %v", err)
	}
}

func TestLockMemory_EmptyBuffer(t *testing.T) {
	// Test with empty buffer - should not fail
	buf := make([]byte, 0)

	err := secure.LockMemory(buf)
	if err != nil {
		t.Errorf("LockMemory failed for empty buffer: %v", err)
	}

	err = secure.UnlockMemory(buf)
	if err != nil {
		t.Errorf("UnlockMemory failed for empty buffer: %v", err)
	}
}

func TestMemoryZero(t *testing.T) {
	// Create test buffer with non-zero data
	buf := make([]byte, 1024)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}

	// Verify buffer is not all zeros
	allZeros := true
	for _, b := range buf {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Fatal("test buffer is already all zeros")
	}

	// Zero the buffer
	secure.Zero(buf)

	// Verify buffer is zeroed
	for i, b := range buf {
		if b != 0 {
			t.Errorf("byte at index %d is not zero after Zero(): got %d", i, b)
		}
	}
}

func TestMemoryZero_EmptyBuffer(t *testing.T) {
	// Test with empty buffer - should not panic
	buf := make([]byte, 0)
	secure.Zero(buf)
}

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"equal slices", []byte("hello"), []byte("hello"), true},
		{"different slices", []byte("hello"), []byte("world"), false},
		{"different lengths", []byte("hello"), []byte("hi"), false},
		{"empty slices", []byte{}, []byte{}, true},
		{"one empty", []byte("hello"), []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := secure.SecureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("SecureCompare(%q, %q) = %v, expected %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

func TestMemoryLocking_CrossPlatform(t *testing.T) {
	// Test that memory locking works correctly on all platforms
	buf := make([]byte, 8192)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}

	// Save original data
	original := make([]byte, len(buf))
	copy(original, buf)

	// Lock memory
	err := secure.LockMemory(buf)
	if err != nil {
		// Log error but continue - mlock may not be available
		t.Logf("LockMemory returned error (may be expected): %v", err)

		// On Windows, this should be nil (no-op)
		if runtime.GOOS == "windows" && err != nil {
			t.Errorf("expected LockMemory to succeed on Windows, got error: %v", err)
		}
	}

	// Verify data is unchanged
	if !bytes.Equal(buf, original) {
		t.Error("buffer data changed after LockMemory")
	}

	// Unlock memory
	err = secure.UnlockMemory(buf)
	if err != nil {
		t.Logf("UnlockMemory returned error: %v", err)

		// On Windows, this should be nil (no-op)
		if runtime.GOOS == "windows" && err != nil {
			t.Errorf("expected UnlockMemory to succeed on Windows, got error: %v", err)
		}
	}

	// Verify data is still unchanged
	if !bytes.Equal(buf, original) {
		t.Error("buffer data changed after UnlockMemory")
	}
}
