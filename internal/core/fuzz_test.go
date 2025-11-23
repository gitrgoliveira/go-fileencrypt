//go:build go1.25
// +build go1.25

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
)

func FuzzDecryptor(f *testing.F) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, err := NewEncryptor(key)
	if err != nil {
		f.Fatalf("NewEncryptor failed: %v", err)
	}
	var buf bytes.Buffer
	plaintext := []byte("test data")
	_ = enc.EncryptStream(context.Background(), bytes.NewReader(plaintext), &buf)
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		dec, err := NewDecryptor(key)
		if err != nil {
			t.Fatalf("NewDecryptor failed: %v", err)
		}
		_ = dec.DecryptStream(context.Background(), bytes.NewReader(data), &bytes.Buffer{})
	})
}

func FuzzEncryptor(f *testing.F) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	f.Add([]byte("test"))
	f.Add([]byte(""))
	f.Add(make([]byte, MaxChunkSize))
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		enc, err := NewEncryptor(key)
		if err != nil {
			t.Fatalf("NewEncryptor failed: %v", err)
		}
		dec, err := NewDecryptor(key)
		if err != nil {
			t.Fatalf("NewDecryptor failed: %v", err)
		}
		var encBuf, decBuf bytes.Buffer
		err = enc.EncryptStream(context.Background(), bytes.NewReader(plaintext), &encBuf)
		if err != nil {
			return
		}
		err = dec.DecryptStream(context.Background(), &encBuf, &decBuf)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(plaintext, decBuf.Bytes()) {
			t.Fatal("plaintext mismatch after round-trip")
		}
	})
}
