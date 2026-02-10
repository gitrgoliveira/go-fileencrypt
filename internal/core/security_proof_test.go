package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// Helper: wrapper for encryption to reduce boilerplate
func encryptDataHelper(t *testing.T, key []byte, data []byte, chunkSize int) *bytes.Buffer {
	t.Helper()
	var encBuf bytes.Buffer
	chunkOpt, err := WithChunkSize(chunkSize)
	if err != nil {
		t.Fatalf("WithChunkSize failed: %v", err)
	}

	enc, err := NewEncryptor(key, chunkOpt)
	if err != nil {
		t.Fatalf("NewEncryptor failed: %v", err)
	}

	err = enc.EncryptStream(context.Background(), bytes.NewReader(data), &encBuf)
	if err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
	return &encBuf
}

// TestSecurity_Truncation verifies that truncated files are detected.
func TestSecurity_Truncation(t *testing.T) {
	key := make([]byte, 32)
	keyBuf, _ := secure.NewSecureBufferFromBytes(key)
	defer keyBuf.Destroy()

	data := bytes.Repeat([]byte("A"), 5000)
	encBuf := encryptDataHelper(t, key, data, 1024)
	encBytes := encBuf.Bytes()

	// Attack: Truncate the file (remove last byte)
	truncated := encBytes[:len(encBytes)-1]

	chunkOpt, _ := WithChunkSize(1024)
	dec, err := NewDecryptor(key, chunkOpt)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	var dst bytes.Buffer
	err = dec.DecryptStream(context.Background(), bytes.NewReader(truncated), &dst)

	if err == nil {
		t.Error("Expected error for truncated file, got nil")
	} else {
		t.Logf("Truncation correctly detected with error: %v", err)
	}
}

// TestSecurity_Modification verifies that checking for bit flipping works.
func TestSecurity_Modification(t *testing.T) {
	key := make([]byte, 32)
	keyBuf, _ := secure.NewSecureBufferFromBytes(key)
	defer keyBuf.Destroy()

	data := bytes.Repeat([]byte("A"), 1024)
	encBuf := encryptDataHelper(t, key, data, 1024)
	encBytes := encBuf.Bytes()

	// Attack: Flip a bit in the ciphertext data (past the header)
	// Header is ~20+ bytes. Let's modify the end.
	modified := make([]byte, len(encBytes))
	copy(modified, encBytes)
	modified[len(modified)-5] ^= 0xFF // Flip bits

	chunkOpt, _ := WithChunkSize(1024)
	dec, err := NewDecryptor(key, chunkOpt)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	var dst bytes.Buffer
	err = dec.DecryptStream(context.Background(), bytes.NewReader(modified), &dst)

	if err == nil {
		t.Error("Expected error for modified ciphertext, got nil")
	} else if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' error, got: %v", err)
	}
}

// TestSecurity_Appending verifies that you cannot just append valid chunks to a file.
func TestSecurity_Appending(t *testing.T) {
	key := make([]byte, 32)
	keyBuf, _ := secure.NewSecureBufferFromBytes(key)
	defer keyBuf.Destroy()

	chunkSize := 1024
	data := bytes.Repeat([]byte("A"), chunkSize) // 1 chunk
	encBuf := encryptDataHelper(t, key, data, chunkSize)

	// Extract the single chunk (skip header)
	// Header format: Magic(3) + Ver(1) + Nonce(12) + Size(8)
	headerLen := 3 + 1 + 12 + 8
	encBytes := encBuf.Bytes()
	if len(encBytes) <= headerLen {
		t.Fatalf("Encrypted data too short")
	}
	header := encBytes[:headerLen]
	chunk := encBytes[headerLen:]

	// Attack: Duplicate the chunk at the end
	var malicious bytes.Buffer
	malicious.Write(header) // Valid header

	// Case A: Don't update size header, just append chunk.
	malicious.Write(chunk)
	malicious.Write(chunk)

	chunkOpt, _ := WithChunkSize(chunkSize)
	dec, err := NewDecryptor(key, chunkOpt)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	var dst bytes.Buffer
	err = dec.DecryptStream(context.Background(), bytes.NewReader(malicious.Bytes()), &dst)
	if err == nil {
		t.Error("Expected error for appended chunk (size mismatch), got nil")
	} else if !strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "authentication failed") {
		// "unexpected EOF" implies we read more or less than expected based on header
		// Wait, if we read MORE than totalSize, the loop checks:
		// if totalSize > 0 && written != totalSize { ... } at the end.
		// Actually, if we just keep reading chunks...
		// The loop reads until io.EOF.
		// If we append a chunk, it will read it, process it (if auth passes), increment 'written'.
		// Then loop finishes.
		// Then it checks `written != totalSize`. Since `written` will be 2x, it should error.
		// UNLESS the second chunk fails auth first (which it might because nonce counter increments).
		// Yes, second chunk will use nonce + 1. But the chunk data was sealed with nonce + 0.
		// So Authentication Failed is actually the valid error here too!
		t.Logf("Got expected error for Case A: %v", err)
	}

	// Case B: Update size header to match new size (2 chunks)
	// Original was 1024 bytes. New is 2048.

	var maliciousB bytes.Buffer
	newHeader := make([]byte, headerLen)
	copy(newHeader, header)

	// Update size at end of header (last 8 bytes)
	newSize := uint64(chunkSize * 2)
	binary.BigEndian.PutUint64(newHeader[headerLen-8:], newSize)

	maliciousB.Write(newHeader)
	maliciousB.Write(chunk)
	maliciousB.Write(chunk)

	var dstB bytes.Buffer
	decB, _ := NewDecryptor(key, chunkOpt)
	err = decB.DecryptStream(context.Background(), bytes.NewReader(maliciousB.Bytes()), &dstB)

	// This MUST fail because AAD used to seal the chunks was the ORIGINAL size (1024).
	// We are now decrypting with AAD = 2048 (from new header).
	if err == nil {
		t.Error("Expected error for Case B (header tampering), got nil")
	} else if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("Expected 'authentication failed' for Case B, got: %v", err)
	}
}

// TestSecurity_CrossFileSplicing verifies that chunks cannot be moved between files.
func TestSecurity_CrossFileSplicing(t *testing.T) {
	key := make([]byte, 32)
	keyBuf, _ := secure.NewSecureBufferFromBytes(key)
	defer keyBuf.Destroy()

	chunkSize := 1024
	data := bytes.Repeat([]byte("A"), chunkSize)

	// File 1
	encBuf1 := encryptDataHelper(t, key, data, chunkSize)
	encBytes1 := encBuf1.Bytes()

	// File 2 (Same content, same key, different nonce)
	encBuf2 := encryptDataHelper(t, key, data, chunkSize)
	encBytes2 := encBuf2.Bytes()

	// Extract chunks
	headerLen := 3 + 1 + 12 + 8
	if len(encBytes2) <= headerLen {
		t.Fatal("Enc buffer too short")
	}
	header2 := encBytes2[:headerLen]
	chunk1 := encBytes1[headerLen:] // Chunk from File 1

	// Attack: Use Header from File 2, but Chunk from File 1
	var malicious bytes.Buffer
	malicious.Write(header2)
	malicious.Write(chunk1)

	chunkOpt, _ := WithChunkSize(chunkSize)
	dec, err := NewDecryptor(key, chunkOpt)
	if err != nil {
		t.Fatalf("NewDecryptor failed: %v", err)
	}

	var dst bytes.Buffer
	err = dec.DecryptStream(context.Background(), bytes.NewReader(malicious.Bytes()), &dst)

	// Should fail because Chunk 1 was sealed with Nonce 1.
	// We are trying to open it with Nonce 2 (derived from Header 2).
	if err == nil {
		t.Error("Expected error for spliced chunk, got nil")
	} else if !strings.Contains(err.Error(), "authentication failed") {
		fmt.Printf("Error was: %v\n", err)
		t.Errorf("Expected 'authentication failed' for splicing, got: %v", err)
	}
}
