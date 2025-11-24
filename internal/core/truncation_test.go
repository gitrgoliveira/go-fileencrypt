package core_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/internal/core"
)

func TestDecryptStream_Truncation(t *testing.T) {
	// 1. Setup key and data
	key := make([]byte, 32) // Zero key for test
	data := []byte("Hello World, this is a test of truncation!")

	// 2. Encrypt
	enc, err := core.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	var encryptedBuf bytes.Buffer
	if err := enc.EncryptStream(context.Background(), bytes.NewReader(data), &encryptedBuf); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}

	// 3. Truncate (remove the last chunk)
	// The format is: Magic(4) + Ver(1) + Nonce(12) + Size(8) + [ChunkSize(4) + ChunkData(N)]...
	// We want to cut off the last chunk.
	// Since our data is small, it's likely just one chunk.
	// Let's make sure we have enough data for 2 chunks if we force small chunk size,
	// or just chop off the last few bytes of the single chunk.
	// If we chop bytes *within* a chunk, GCM auth will fail (good).
	// If we chop *entire* chunks, GCM auth won't run for that chunk.
	// We need to simulate a file that is valid up to a point, but missing the end.

	ciphertext := encryptedBuf.Bytes()

	// Case 1: Truncate inside a chunk (should fail auth)
	truncated1 := ciphertext[:len(ciphertext)-1]

	dec, err := core.NewDecryptor(key)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	var decryptedBuf1 bytes.Buffer
	err = dec.DecryptStream(context.Background(), bytes.NewReader(truncated1), &decryptedBuf1)
	if err == nil {
		t.Error("DecryptStream should have failed for partial chunk truncation (GCM auth failure expected)")
	} else {
		t.Logf("Partial truncation correctly failed: %v", err)
	}

	// Case 2: Truncate an entire chunk (if we had multiple)
	// Let's try to encrypt with small chunk size to get multiple chunks.
	opt, err := core.WithChunkSize(10)
	if err != nil {
		t.Fatalf("WithChunkSize failed: %v", err)
	}
	encSmall, _ := core.NewEncryptor(key, opt) // 10 bytes chunks
	var encBufSmall bytes.Buffer
	// Pass size hint so the header contains the total size, enabling the truncation check
	encSmall.EncryptStream(context.Background(), bytes.NewReader(data), &encBufSmall, int64(len(data)))

	cipherSmall := encBufSmall.Bytes()
	// We expect multiple chunks.
	// Format: Header + (Size+Chunk) + (Size+Chunk) ...
	// If we remove the last (Size+Chunk), does it error?

	// We need to parse the structure to find the last chunk boundary.
	// Or just hack it: we know the logic.
	// Let's just remove the last X bytes where X is the size of the last chunk + 4 bytes overhead.
	// Actually, let's just remove the last byte and see what happens.
	// If we remove the last byte of the *last chunk*, it fails auth.
	// If we remove the *entire last chunk*, does it fail?

	// Let's construct a truncated stream that ends exactly at a chunk boundary but is missing the final chunk(s).
	// Since we don't easily know the exact boundary without parsing, let's just try to decrypt a prefix that we know is "valid so far" but incomplete.
	// The header contains the total size.

	// Let's take the first 50 bytes (header is ~25 bytes, plus one small chunk).
	// Total data is ~40 bytes. Header is 4+1+12+8 = 25 bytes.
	// Chunk 1: 4 bytes size + 10 bytes data + 16 bytes tag = 30 bytes.
	// So 50 bytes includes Header + part of Chunk 1.

	// Case 2: Truncate exactly at a chunk boundary (e.g., just the header)
	// Header size = Magic(3) + Ver(1) + Nonce(12) + Size(8) = 24 bytes
	// If we provide just the header, the decryptor reads the header, sees the expected size,
	// then tries to read the first chunk size, gets EOF, and exits the loop cleanly.
	// This is the vulnerability: it returns nil error but hasn't decrypted anything.

	headerSize := 3 + 1 + 12 + 8
	if len(cipherSmall) >= headerSize {
		truncated2 := cipherSmall[:headerSize]
		var decryptedBuf2 bytes.Buffer
		err = dec.DecryptStream(context.Background(), bytes.NewReader(truncated2), &decryptedBuf2)
		if err == nil {
			t.Errorf("VULNERABILITY CONFIRMED: DecryptStream succeeded despite missing all chunks! Decrypted bytes: %d, Expected: %d", decryptedBuf2.Len(), len(data))
		} else {
			t.Logf("Truncation correctly caught: %v", err)
		}
	} else {
		t.Fatalf("Ciphertext too small for test: %d", len(cipherSmall))
	}
}
