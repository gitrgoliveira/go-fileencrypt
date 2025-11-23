/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// benchmark_test.go: Performance benchmarks for go-fileencrypt
package benchmark

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitrgoliveira/go-fileencrypt"
)

// BenchmarkEncryptFile_1MB benchmarks encryption of a 1MB file
func BenchmarkEncryptFile_1MB(b *testing.B) {
	benchmarkEncryptFile(b, 1*1024*1024)
}

// BenchmarkEncryptFile_10MB benchmarks encryption of a 10MB file
func BenchmarkEncryptFile_10MB(b *testing.B) {
	benchmarkEncryptFile(b, 10*1024*1024)
}

// BenchmarkEncryptFile_100MB benchmarks encryption of a 100MB file
func BenchmarkEncryptFile_100MB(b *testing.B) {
	benchmarkEncryptFile(b, 100*1024*1024)
}

// BenchmarkEncryptFile_1GB benchmarks encryption of a 1GB file
// Target: <120s on Intel i5-8400 (6-core, 2.8GHz, circa 2018)
func BenchmarkEncryptFile_1GB(b *testing.B) {
	benchmarkEncryptFile(b, 1*1024*1024*1024)
}

// BenchmarkDecryptFile_1MB benchmarks decryption of a 1MB file
func BenchmarkDecryptFile_1MB(b *testing.B) {
	benchmarkDecryptFile(b, 1*1024*1024)
}

// BenchmarkDecryptFile_10MB benchmarks decryption of a 10MB file
func BenchmarkDecryptFile_10MB(b *testing.B) {
	benchmarkDecryptFile(b, 10*1024*1024)
}

// BenchmarkDecryptFile_100MB benchmarks decryption of a 100MB file
func BenchmarkDecryptFile_100MB(b *testing.B) {
	benchmarkDecryptFile(b, 100*1024*1024)
}

// BenchmarkDecryptFile_1GB benchmarks decryption of a 1GB file
// Target: <120s on Intel i5-8400 (6-core, 2.8GHz, circa 2018)
func BenchmarkDecryptFile_1GB(b *testing.B) {
	benchmarkDecryptFile(b, 1*1024*1024*1024)
}

// benchmarkEncryptFile is a helper function for encryption benchmarks
func benchmarkEncryptFile(b *testing.B, size int64) {
	// Create temp directory
	tmpDir := b.TempDir()

	// Create test file with specified size
	srcFile := filepath.Join(tmpDir, "plaintext.bin")
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(srcFile, data, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ctx := context.Background()

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		encFile := filepath.Join(tmpDir, fmt.Sprintf("encrypted_%d.enc", i%10))
		if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
			b.Fatalf("EncryptFile failed: %v", err)
		}
	}

	// Report throughput
	b.SetBytes(size)
}

// benchmarkDecryptFile is a helper function for decryption benchmarks
func benchmarkDecryptFile(b *testing.B, size int64) {
	// Create temp directory
	tmpDir := b.TempDir()

	// Create test file with specified size
	srcFile := filepath.Join(tmpDir, "plaintext.bin")
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(srcFile, data, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ctx := context.Background()

	// Encrypt the file once for decryption benchmarks
	encFile := filepath.Join(tmpDir, "encrypted.enc")
	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		b.Fatalf("EncryptFile failed: %v", err)
	}

	// Reset timer to exclude setup time
	b.ResetTimer()

	// Run benchmark
	for i := 0; i < b.N; i++ {
		dstFile := filepath.Join(tmpDir, fmt.Sprintf("decrypted_%d.bin", i%10))
		if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, key); err != nil {
			b.Fatalf("DecryptFile failed: %v", err)
		}
	}

	// Report throughput
	b.SetBytes(size)
}

// BenchmarkPBKDF2 benchmarks key derivation performance
func BenchmarkPBKDF2(b *testing.B) {
	password := []byte("test password for benchmarking")
	salt := make([]byte, 32)
	iterations := 600000 // Default OWASP 2023
	keyLen := 32

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := fileencrypt.DeriveKeyPBKDF2(password, salt, iterations, keyLen)
		if err != nil {
			b.Fatalf("DeriveKeyPBKDF2 failed: %v", err)
		}
	}
}

// BenchmarkChunkSize tests different chunk sizes
func BenchmarkChunkSize_64KB(b *testing.B) {
	benchmarkWithChunkSize(b, 64*1024, 10*1024*1024)
}

func BenchmarkChunkSize_256KB(b *testing.B) {
	benchmarkWithChunkSize(b, 256*1024, 10*1024*1024)
}

func BenchmarkChunkSize_1MB(b *testing.B) {
	benchmarkWithChunkSize(b, 1*1024*1024, 10*1024*1024)
}

func BenchmarkChunkSize_4MB(b *testing.B) {
	benchmarkWithChunkSize(b, 4*1024*1024, 10*1024*1024)
}

func benchmarkWithChunkSize(b *testing.B, chunkSize int, fileSize int64) {
	tmpDir := b.TempDir()

	// Create test file
	srcFile := filepath.Join(tmpDir, "plaintext.bin")
	data := make([]byte, fileSize)
	if err := os.WriteFile(srcFile, data, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	key := make([]byte, 32)
	ctx := context.Background()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		encFile := filepath.Join(tmpDir, "encrypted.enc")
		chunkOpt, err := fileencrypt.WithChunkSize(chunkSize)
		if err != nil {
			b.Fatalf("WithChunkSize failed: %v", err)
		}
		if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key, chunkOpt); err != nil {
			b.Fatalf("EncryptFile failed: %v", err)
		}
	}

	b.SetBytes(fileSize)
}

// BenchmarkMemoryOperations benchmarks secure memory operations
func BenchmarkMemoryZero(b *testing.B) {
	data := make([]byte, 4096)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Fill with data
		for j := range data {
			data[j] = byte(j % 256)
		}
		// Zero it
		for j := range data {
			data[j] = 0
		}
	}

	b.SetBytes(4096)
}
