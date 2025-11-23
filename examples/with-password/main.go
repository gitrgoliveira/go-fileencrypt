/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// Example of password-based encryption using PBKDF2
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/gitrgoliveira/go-fileencrypt"
	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

func main() {
	fmt.Println("=== Password-Based Encryption Example ===")
	fmt.Println()

	// Step 1: Get password (in real app, use secure input)
	password := []byte("MySecurePassword123!")
	fmt.Println("✓ Using password for encryption")

	// Step 2: Generate a random salt
	salt, err := fileencrypt.GenerateSalt(fileencrypt.DefaultSaltSize)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}
	fmt.Printf("✓ Generated %d-byte salt\n", len(salt))

	// Step 3: Derive encryption key from password using PBKDF2
	key, err := fileencrypt.DeriveKeyPBKDF2(
		password,
		salt,
		fileencrypt.DefaultPBKDF2Iterations, // 600,000 iterations (OWASP 2023)
		fileencrypt.DefaultKeySize,          // 32 bytes for AES-256
	)
	if err != nil {
		log.Fatalf("Failed to derive key: %v", err)
	}
	defer secure.Zero(key) // Always zero sensitive data when done
	fmt.Printf("✓ Derived 32-byte key using PBKDF2 (%d iterations)\n",
		fileencrypt.DefaultPBKDF2Iterations)

	// Step 4: Create a sample file
	plaintext := []byte("Secret document with sensitive information.")
	srcFile := "secret.txt"
	if err := os.WriteFile(srcFile, plaintext, 0600); err != nil {
		log.Fatalf("Failed to create plaintext file: %v", err)
	}
	defer os.Remove(srcFile)
	fmt.Printf("✓ Created plaintext file: %s\n", srcFile)

	// Step 5: Encrypt the file
	encFile := "secret.enc"
	ctx := context.Background()

	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	defer os.Remove(encFile)
	fmt.Printf("✓ Encrypted file saved to: %s\n", encFile)

	// Important: In a real application, you must save the salt alongside
	// the encrypted file (e.g., prepend to file or store separately)
	// The same salt is needed for decryption!
	fmt.Println("\n⚠️  IMPORTANT: Save the salt for decryption!")
	fmt.Printf("   Salt (hex): %x\n", salt)

	// Step 6: Simulate decryption (re-derive key from password + salt)
	fmt.Println("\n--- Simulating Decryption ---")

	// Re-derive key from password and salt
	keyForDecrypt, err := fileencrypt.DeriveKeyPBKDF2(
		password,
		salt,
		fileencrypt.DefaultPBKDF2Iterations,
		fileencrypt.DefaultKeySize,
	)
	if err != nil {
		log.Fatalf("Failed to re-derive key: %v", err)
	}
	defer secure.Zero(keyForDecrypt)
	fmt.Println("✓ Re-derived key from password and salt")

	// Decrypt the file
	dstFile := "decrypted_secret.txt"
	if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, keyForDecrypt); err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	defer os.Remove(dstFile)
	fmt.Printf("✓ Decrypted file saved to: %s\n", dstFile)

	// Step 7: Verify the decrypted content
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
	fmt.Println("\nSecurity Notes:")
	fmt.Println("• Never hardcode passwords in production code")
	fmt.Println("• Always save the salt with the encrypted file")
	fmt.Println("• Use secure password input methods (e.g., terminal.ReadPassword)")
	fmt.Println("• Consider using a minimum of 210,000 iterations (or 600,000 for OWASP 2023)")
}
