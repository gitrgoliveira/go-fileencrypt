/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// Example of encrypting large files with progress tracking
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func main() {
	fmt.Println("=== Large File Encryption Example ===")
	fmt.Println()

	// Step 1: Generate encryption key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	defer fileencrypt.ZeroKey(key) // Always zero sensitive data
	fmt.Println("✓ Generated encryption key")

	// Step 2: Create a large test file (100MB)
	fileSize := 100 * 1024 * 1024 // 100MB
	srcFile := "large_file.bin"
	fmt.Printf("Creating %dMB test file...\n", fileSize/(1024*1024))

	if err := createLargeFile(srcFile, int64(fileSize)); err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(srcFile)
	fmt.Printf("✓ Created test file: %s\n", srcFile)

	// Step 3: Encrypt with progress tracking and timeout
	encFile := "large_file.enc"

	// Set a reasonable timeout for large files (5 minutes for 100MB)
	// Adjust based on file size and expected performance
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Println("\nEncrypting (with 5 minute timeout)...")
	startTime := time.Now()

	chunkOpt, err := fileencrypt.WithChunkSize(1 * 1024 * 1024)
	if err != nil {
		log.Fatalf("Invalid chunk size: %v", err)
	}
	err = fileencrypt.EncryptFile(ctx, srcFile, encFile, key,
		fileencrypt.WithProgress(func(progress float64) {
			// progress is a fraction between 0.0 and 1.0
			percent := progress * 100
			bar := progressBar(progress, 40)
			fmt.Printf("\r  Progress: %s %.1f%%", bar, percent)
		}),
		chunkOpt, // 1MB chunks
	)

	if err != nil {
		if err == context.DeadlineExceeded {
			log.Fatalf("\nEncryption timed out - file too large or system too slow")
		}
		log.Fatalf("\nEncryption failed: %v", err)
	}

	encryptDuration := time.Since(startTime)
	fmt.Printf("\n✓ Encryption complete in %v\n", encryptDuration)

	// Get encrypted file size
	encInfo, _ := os.Stat(encFile)
	fmt.Printf("  Original size: %d bytes\n", fileSize)
	fmt.Printf("  Encrypted size: %d bytes (overhead: %d bytes)\n",
		encInfo.Size(), encInfo.Size()-int64(fileSize))

	defer os.Remove(encFile)

	// Step 4: Decrypt with progress tracking (reuse context with same timeout)
	dstFile := "large_file_decrypted.bin"

	fmt.Println("\nDecrypting (with same timeout)...")
	startTime = time.Now()

	err = fileencrypt.DecryptFile(ctx, encFile, dstFile, key,
		fileencrypt.WithProgress(func(progress float64) {
			percent := progress * 100
			bar := progressBar(progress, 40)
			fmt.Printf("\r  Progress: %s %.1f%%", bar, percent)
		}),
	)

	if err != nil {
		log.Fatalf("\nDecryption failed: %v", err)
	}

	decryptDuration := time.Since(startTime)
	fmt.Printf("\n✓ Decryption complete in %v\n", decryptDuration)

	defer os.Remove(dstFile)

	// Step 5: Verify file integrity
	srcInfo, _ := os.Stat(srcFile)
	dstInfo, _ := os.Stat(dstFile)

	if srcInfo.Size() == dstInfo.Size() {
		fmt.Println("\n✓ SUCCESS: File sizes match!")
		fmt.Printf("  Original size:  %d bytes\n", srcInfo.Size())
		fmt.Printf("  Decrypted size: %d bytes\n", dstInfo.Size())
	} else {
		log.Fatalf("ERROR: File size mismatch")
	}

	// Performance summary
	fmt.Println("\n=== Performance Summary ===")
	encryptSpeed := float64(fileSize) / encryptDuration.Seconds() / (1024 * 1024)
	decryptSpeed := float64(fileSize) / decryptDuration.Seconds() / (1024 * 1024)
	fmt.Printf("Encryption speed: %.2f MB/s\n", encryptSpeed)
	fmt.Printf("Decryption speed: %.2f MB/s\n", decryptSpeed)

	fmt.Println("\n=== Example Complete ===")
}

// createLargeFile creates a file of specified size with pseudo-random data
func createLargeFile(filename string, size int64) error {
	// #nosec G304 -- Example code with controlled file paths
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write in 1MB chunks
	chunkSize := 1024 * 1024
	buffer := make([]byte, chunkSize)

	for written := int64(0); written < size; {
		toWrite := chunkSize
		if size-written < int64(chunkSize) {
			toWrite = int(size - written)
		}

		// Fill buffer with pseudo-random data
		for i := 0; i < toWrite; i++ {
			buffer[i] = byte((written + int64(i)) % 256)
		}

		n, err := f.Write(buffer[:toWrite])
		if err != nil {
			return err
		}
		written += int64(n)
	}

	return nil
}

// progressBar creates a visual progress bar
func progressBar(progress float64, width int) string {
	filled := int(progress * float64(width))
	if filled > width {
		filled = width
	}

	bar := "["
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "="
		} else if i == filled {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	return bar
}
