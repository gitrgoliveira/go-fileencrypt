/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// checksum_test.go: Checksum tests for go-fileencrypt
package core

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestChecksumCalculateAndVerify(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test.bin")

	// Create test file
	testData := make([]byte, 1024)
	if _, err := rand.Read(testData); err != nil {
		t.Fatalf("failed to generate test data: %v", err)
	}

	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Calculate checksum
	sum, err := CalculateChecksum(testPath)
	if err != nil {
		t.Fatalf("CalculateChecksum failed: %v", err)
	}

	if len(sum) != 32 { // SHA256 is 32 bytes
		t.Errorf("expected checksum length 32, got %d", len(sum))
	}

	// Verify checksum
	ok, err := VerifyChecksum(testPath, sum)
	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}

	if !ok {
		t.Error("checksum verification failed for matching file")
	}
}

func TestChecksumVerify_Mismatch(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test.bin")

	// Create test file
	testData := []byte("Original data")
	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Calculate checksum
	sum, err := CalculateChecksum(testPath)
	if err != nil {
		t.Fatalf("CalculateChecksum failed: %v", err)
	}

	// Modify file
	modifiedData := []byte("Modified data")
	if err := os.WriteFile(testPath, modifiedData, 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// Verify checksum - should fail
	ok, err := VerifyChecksum(testPath, sum)
	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}

	if ok {
		t.Error("checksum verification succeeded for mismatched file (expected failure)")
	}
}

func TestChecksumCalculate_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "does_not_exist.bin")

	_, err := CalculateChecksum(nonExistentPath)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	t.Logf("Got expected error: %v", err)
}

func TestChecksumVerify_WrongLength(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test.bin")

	testData := []byte("Test data")
	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Use wrong length checksum
	wrongSum := make([]byte, 16) // Should be 32 for SHA256

	ok, err := VerifyChecksum(testPath, wrongSum)
	if err != nil {
		t.Fatalf("VerifyChecksum failed: %v", err)
	}

	if ok {
		t.Error("checksum verification succeeded with wrong length checksum")
	}
}

func TestCalculateChecksumHex(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test.bin")

	testData := []byte("Test data for hex checksum")
	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hexSum, err := CalculateChecksumHex(testPath)
	if err != nil {
		t.Fatalf("CalculateChecksumHex failed: %v", err)
	}

	// SHA256 hex string should be 64 characters (32 bytes * 2)
	if len(hexSum) != 64 {
		t.Errorf("expected hex checksum length 64, got %d", len(hexSum))
	}

	// Verify it's valid hex
	for _, c := range hexSum {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("invalid hex character: %c", c)
		}
	}
}

func TestVerifyChecksumHex(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "test.bin")

	testData := []byte("Test data for hex verification")
	if err := os.WriteFile(testPath, testData, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Calculate hex checksum
	hexSum, err := CalculateChecksumHex(testPath)
	if err != nil {
		t.Fatalf("CalculateChecksumHex failed: %v", err)
	}

	// Verify with correct checksum
	ok, err := VerifyChecksumHex(testPath, hexSum)
	if err != nil {
		t.Fatalf("VerifyChecksumHex failed: %v", err)
	}
	if !ok {
		t.Error("hex checksum verification failed for matching file")
	}

	// Verify with incorrect checksum
	wrongHex := "0000000000000000000000000000000000000000000000000000000000000000"
	ok, err = VerifyChecksumHex(testPath, wrongHex)
	if err != nil {
		t.Fatalf("VerifyChecksumHex failed: %v", err)
	}
	if ok {
		t.Error("hex checksum verification succeeded for wrong checksum")
	}
}
