/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package crypto

import (
	"errors"
	"fmt"
	"os"
)

// SanitizeError removes sensitive details for external consumption
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, ErrInvalidKey):
		return fmt.Errorf("invalid encryption key")
	case errors.Is(err, ErrChunkSize):
		return fmt.Errorf("corrupted encrypted file")
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("insufficient permissions")
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("file not found")
	default:
		// Generic error for unknown cases
		return fmt.Errorf("encryption operation failed")
	}
}

// Error types for file encryption
var (
	ErrInvalidKey      = fmt.Errorf("invalid key")
	ErrInvalidNonce    = fmt.Errorf("invalid nonce")
	ErrChunkSize       = fmt.Errorf("invalid chunk size")
	ErrChecksum        = fmt.Errorf("checksum mismatch")
	ErrContextCanceled = fmt.Errorf("context canceled")
)

// EncryptionError represents an encryption/decryption error with context
type EncryptionError struct {
	Op       string // Operation: "encrypt", "decrypt", "generate_key", etc.
	Path     string // File path being operated on
	ChunkNum int    // Chunk number if applicable (-1 if not chunked operation)
	Err      error  // Underlying error
}

func (e *EncryptionError) Error() string {
	if e.ChunkNum >= 0 {
		return fmt.Sprintf("%s %s (chunk %d): %v", e.Op, e.Path, e.ChunkNum, e.Err)
	}
	return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Err)
}

func (e *EncryptionError) Unwrap() error {
	return e.Err
}

// NewEncryptionError creates a new EncryptionError
func NewEncryptionError(op, path string, chunkNum int, err error) *EncryptionError {
	return &EncryptionError{
		Op:       op,
		Path:     path,
		ChunkNum: chunkNum,
		Err:      err,
	}
}

// WrapError adds context to an error
func WrapError(context string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}
