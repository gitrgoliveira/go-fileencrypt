/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// secure_buffer_test.go: SecureBuffer tests for go-fileencrypt
package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/internal/crypto"
)

func TestSecureBufferDestroy(t *testing.T) {
	// Generate test key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create SecureBuffer
	buf, err := crypto.NewSecureBufferFromBytes(key)
	if err != nil {
		t.Fatalf("NewSecureBufferFromBytes failed: %v", err)
	}

	// Verify data matches
	data := buf.Data()
	if !bytes.Equal(data, key) {
		t.Fatal("SecureBuffer data does not match original key")
	}

	// Destroy buffer
	buf.Destroy()

	// Verify data is zeroed
	data = buf.Data()
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d is not zero after Destroy(): got %d", i, b)
		}
	}
}

func TestSecureBufferCreate(t *testing.T) {
	key := []byte("test key material for buffer")

	buf, err := crypto.NewSecureBufferFromBytes(key)
	if err != nil {
		t.Fatalf("NewSecureBufferFromBytes failed: %v", err)
	}
	defer buf.Destroy()

	data := buf.Data()
	if len(data) != len(key) {
		t.Errorf("expected buffer length %d, got %d", len(key), len(data))
	}

	if !bytes.Equal(data, key) {
		t.Error("SecureBuffer data does not match input")
	}
}

func TestSecureBufferMultipleDestroy(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	buf, err := crypto.NewSecureBufferFromBytes(key)
	if err != nil {
		t.Fatalf("NewSecureBufferFromBytes failed: %v", err)
	}

	// Call Destroy multiple times - should be safe
	buf.Destroy()
	buf.Destroy()
	buf.Destroy()

	// Verify data is still zeroed
	data := buf.Data()
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d is not zero after multiple Destroy(): got %d", i, b)
		}
	}
}
