/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// Example of password-based encryption using Argon2id (recommended for new applications)
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func main() {
	fmt.Println("=== Password-Based Encryption with Argon2id ===")
	fmt.Println()

	// Password for encryption
	password := []byte("MySecurePassword123!")
	fmt.Println("✓ Using password for encryption")

	// Step 1: Generate a random salt
	salt, err := fileencrypt.GenerateSalt(fileencrypt.DefaultSaltSize)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}
	defer fileencrypt.ZeroKey(salt) // Clean up salt
	fmt.Printf("✓ Generated %d-byte salt\n", len(salt))

	// Step 2: Derive key using Argon2id (OWASP 2023 recommended parameters)
	// Argon2id is more resistant to GPU/ASIC attacks than PBKDF2
	key, err := fileencrypt.DeriveKeyArgon2(
		password,
		salt,
		fileencrypt.DefaultArgon2Time,      // 3 iterations
		fileencrypt.DefaultArgon2Memory,    // 64 MB memory cost
		fileencrypt.DefaultArgon2Threads,   // 4 threads (parallelism)
		uint32(fileencrypt.DefaultKeySize), // 32 bytes for AES-256
	)
	if err != nil {
		log.Fatalf("Failed to derive key: %v", err)
	}
	defer fileencrypt.ZeroKey(key) // Always zero sensitive data
	fmt.Printf("✓ Derived 32-byte key using Argon2id (time=3, memory=64MB, threads=4)\n")

	// Step 3: Create plaintext file
	plaintext := "Secret document with sensitive information - protected by Argon2id!"
	srcFile := "secret.txt"
	// #nosec G306 -- example code, file permissions are not critical for demo
	if err := os.WriteFile(srcFile, []byte(plaintext), 0644); err != nil {
		log.Fatalf("Failed to create plaintext file: %v", err)
	}
	defer os.Remove(srcFile)
	fmt.Printf("✓ Created plaintext file: %s\n", srcFile)

	// Step 4: Encrypt the file
	encFile := "secret.enc"
	ctx := context.Background()

	if err := fileencrypt.EncryptFile(ctx, srcFile, encFile, key); err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("✓ Encrypted file saved to: %s\n", encFile)
	defer os.Remove(encFile)

	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Save the salt for decryption!")
	fmt.Printf("   Salt (hex): %s\n", hex.EncodeToString(salt))
	fmt.Println()

	// Step 5: Simulate decryption (in real scenario, user provides password and salt)
	fmt.Println("--- Simulating Decryption ---")

	// Re-derive the key from password and salt
	derivedKey, err := fileencrypt.DeriveKeyArgon2(
		password,
		salt,
		fileencrypt.DefaultArgon2Time,
		fileencrypt.DefaultArgon2Memory,
		fileencrypt.DefaultArgon2Threads,
		uint32(fileencrypt.DefaultKeySize),
	)
	if err != nil {
		log.Fatalf("Failed to re-derive key: %v", err)
	}
	defer fileencrypt.ZeroKey(derivedKey)
	fmt.Println("✓ Re-derived key from password and salt")

	// Decrypt the file
	dstFile := "decrypted_secret.txt"
	if err := fileencrypt.DecryptFile(ctx, encFile, dstFile, derivedKey); err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("✓ Decrypted file saved to: %s\n", dstFile)
	defer os.Remove(dstFile)

	// Step 6: Verify the content
	decrypted, err := os.ReadFile(dstFile)
	if err != nil {
		log.Fatalf("Failed to read decrypted file: %v", err)
	}

	fmt.Println()
	if string(decrypted) == plaintext {
		fmt.Println("✓ SUCCESS: Decrypted content matches original!")
		fmt.Printf("   Original:  %q\n", plaintext)
		fmt.Printf("   Decrypted: %q\n", string(decrypted))
	} else {
		fmt.Println("✗ ERROR: Decrypted content doesn't match!")
	}

	fmt.Println()
	fmt.Println("=== Example Complete ===")
	fmt.Println()
	fmt.Println("Security Notes:")
	fmt.Println("• Argon2id is the recommended algorithm (winner of Password Hashing Competition)")
	fmt.Println("• More resistant to GPU/ASIC attacks than PBKDF2")
	fmt.Println("• Never hardcode passwords in production code")
	fmt.Println("• Always save the salt with the encrypted file")
	fmt.Println("• Use secure password input methods (e.g., terminal.ReadPassword)")
	fmt.Println("• Argon2 parameters: time=3, memory=64MB, threads=4 (OWASP 2023)")
}
