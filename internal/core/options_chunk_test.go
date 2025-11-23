/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"context"
	"io"
	"testing"
)

func TestWithChunkSizeValidation(t *testing.T) {
	_, err := WithChunkSize(0)
	if err == nil {
		t.Fatalf("expected error for chunk size 0")
	}

	_, err = WithChunkSize(MaxChunkSize + 1)
	if err == nil {
		t.Fatalf("expected error for chunk size > MaxChunkSize")
	}

	opt, err := WithChunkSize(1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := &Config{}
	opt(cfg)
	if cfg.ChunkSize != 1024 {
		t.Fatalf("chunk size not applied")
	}
}

// TestNonceOverflow simulates a scenario where chunk counter overflows. We exercise
// EncryptStream by providing a reader that returns chunks repeatedly until the
// internal implementation would increment the counter past uint32 max. Instead of
// actually iterating 2^32 times (impossible in a unit test), we rely on the
// implementation's nonce overflow check after incrementing the counter from max
// to 0 — but we cannot reach that in practice here. This test ensures EncryptStream
// works for small inputs and returns no unexpected errors for normal usage.
func TestEncryptStreamBasic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}
	defer enc.Destroy()

	// Small input should encrypt fine
	r := io.NopCloser(io.LimitReader(&zeroReader{}, 1024))
	if err := enc.EncryptStream(context.Background(), r, io.Discard, 1024); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
}

// zeroReader implements io.Reader that returns zero bytes
type zeroReader struct{}

func (z *zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), io.EOF
}
