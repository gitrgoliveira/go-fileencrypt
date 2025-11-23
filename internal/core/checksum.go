/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// CalculateChecksum computes the SHA-256 checksum of a file.
func CalculateChecksum(path string) ([]byte, error) {
	// #nosec G304 -- file path provided by caller, library is designed for file operations
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// CalculateChecksumHex computes the SHA-256 checksum of a file and returns it as hex string.
func CalculateChecksumHex(path string) (string, error) {
	sum, err := CalculateChecksum(path)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}

// VerifyChecksum checks if the file matches the given checksum
func VerifyChecksum(path string, sum []byte) (bool, error) {
	actual, err := CalculateChecksum(path)
	if err != nil {
		return false, err
	}
	return secure.SecureCompare(actual, sum), nil
}

// VerifyChecksumHex checks if the file matches the given hex-encoded checksum
func VerifyChecksumHex(path string, hexSum string) (bool, error) {
	sum, err := hex.DecodeString(hexSum)
	if err != nil {
		return false, fmt.Errorf("invalid hex checksum: %w", err)
	}
	return VerifyChecksum(path, sum)
}
