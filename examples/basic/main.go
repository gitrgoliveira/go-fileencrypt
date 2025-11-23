/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// Basic example of file encryption and decryption
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func main() {
	fmt.Println("=== Basic File Encryption Example ===")
	fmt.Println()

	// Step 1: Generate a random 32-byte key for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	defer fileencrypt.ZeroKey(key) // Always zero sensitive data
	fmt.Println("✓ Generated 32-byte encryption key")

	// Step 2: Create a sample file
	plaintext := []byte("Hello, World! This is a secret message.")
	srcFile := "plaintext.txt"
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		log.Fatalf("Failed to create plaintext file: %v", err)
	}
	defer os.Remove(srcFile)
	fmt.Printf("✓ Created plaintext file: %s\n", srcFile)

	// Step 3: Encrypt the file
	encFile := "encrypted.enc"
	ctx := context.Background()

	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	defer os.Remove(encFile)
	fmt.Printf("✓ Encrypted file saved to: %s\n", encFile)

	// Step 4: Decrypt the file
	dstFile := "decrypted.txt"
	if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, key); err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	defer os.Remove(dstFile)
	fmt.Printf("✓ Decrypted file saved to: %s\n", dstFile)

	// Step 5: Verify the decrypted content
	decrypted, err := os.ReadFile(dstFile)
	if err != nil {
		log.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decrypted) == string(plaintext) {
		fmt.Println("\n✓ SUCCESS: Decrypted content matches original!")
		fmt.Printf("   Original:  %q\n", string(plaintext))
		fmt.Printf("   Decrypted: %q\n", string(decrypted))
	} else {
		log.Fatalf("ERROR: Decrypted content does not match original")
	}

	fmt.Println("\n=== Example Complete ===")
}
