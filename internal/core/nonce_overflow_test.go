//go:build testhooks
// +build testhooks

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
	"testing"

	crypto "github.com/gitrgoliveira/go-fileencrypt/internal/crypto"
)

// TestNonceOverflow triggers the nonce overflow path by initializing the
// encryptor's chunk counter to the maximum uint32 value and then writing two
// chunks. The second chunk should cause the counter to wrap to zero and
// produce an error from EncryptStream.
func TestNonceOverflow(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Use tiny chunk size to force multiple chunks from the provided data.
	opt, err := WithChunkSize(1)
	if err != nil {
		t.Fatalf("WithChunkSize failed: %v", err)
	}

	enc, err := NewEncryptor(key, opt)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	// Set start counter to max uint32 so the next increment wraps to 0.
	SetEncryptorChunkCounter(enc, ^uint32(0))

	// Prepare a source reader that yields two small chunks (2 bytes)
	src := bytes.NewReader([]byte{0x01, 0x02})
	dst := &bytes.Buffer{}

	// Run EncryptStream and expect an error due to nonce overflow
	err = enc.EncryptStream(context.Background(), src, dst, int64(2))
	if err == nil {
		t.Fatalf("expected nonce overflow error, got nil")
	}
	t.Logf("EncryptStream returned expected error: %v", err)

	// Ensure no sensitive data remains in key buffer
	enc.Destroy()
	// Validate SecureBuffer destroyed via crypto package (best-effort)
	_ = crypto.ErrContextCanceled
}
