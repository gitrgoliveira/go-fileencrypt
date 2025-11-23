/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/gitrgoliveira/go-fileencrypt"
)

func main() {
	tmp := os.TempDir()
	src := filepath.Join(tmp, "example.txt")
	enc := filepath.Join(tmp, "example.txt.enc")
	sha := filepath.Join(tmp, "example.txt.sha256")

	plaintext := []byte("Example data for checksum demo")
	if err := os.WriteFile(src, plaintext, 0600); err != nil {
		log.Fatalf("write src: %v", err)
	}

	// Generate key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("generate key: %v", err)
	}
	defer fileencrypt.ZeroKey(key)

	ctx := context.Background()

	// Encrypt file
	if err := fileencrypt.EncryptFile(ctx, src, enc, key); err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	// Calculate checksum and save sidecar
	sumHex, err := fileencrypt.CalculateChecksumHex(src)
	if err != nil {
		log.Fatalf("calculate checksum: %v", err)
	}
	if err := os.WriteFile(sha, []byte(sumHex), 0600); err != nil {
		log.Fatalf("save checksum: %v", err)
	}
	fmt.Printf("Encrypted %s and saved checksum %s\n", enc, sha)

	// Later: verify checksum
	loadedBytes, err := os.ReadFile(sha) // #nosec G304: example reading a local checksum sidecar file (no user input)
	if err != nil {
		log.Fatalf("load checksum: %v", err)
	}
	loaded := string(loadedBytes)
	ok, err := fileencrypt.VerifyChecksumHex(src, loaded)
	if err != nil {
		log.Fatalf("verify checksum: %v", err)
	}
	if !ok {
		log.Fatalf("checksum mismatch")
	}
	fmt.Println("Checksum verified")
}
