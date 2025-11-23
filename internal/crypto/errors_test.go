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
	"strings"
	"testing"
)

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected string
	}{
		{
			name:     "nil error",
			input:    nil,
			expected: "",
		},
		{
			name:     "ErrInvalidKey",
			input:    ErrInvalidKey,
			expected: "invalid encryption key",
		},
		{
			name:     "wrapped ErrInvalidKey",
			input:    fmt.Errorf("validation failed: %w", ErrInvalidKey),
			expected: "invalid encryption key",
		},
		{
			name:     "ErrChunkSize",
			input:    ErrChunkSize,
			expected: "corrupted encrypted file",
		},
		{
			name:     "os.ErrPermission",
			input:    os.ErrPermission,
			expected: "insufficient permissions",
		},
		{
			name:     "wrapped os.ErrPermission",
			input:    fmt.Errorf("open file: %w", os.ErrPermission),
			expected: "insufficient permissions",
		},
		{
			name:     "os.ErrNotExist",
			input:    os.ErrNotExist,
			expected: "file not found",
		},
		{
			name:     "unknown error",
			input:    fmt.Errorf("random error"),
			expected: "encryption operation failed",
		},
		{
			name:     "custom error",
			input:    errors.New("some custom error"),
			expected: "encryption operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeError(tt.input)

			if tt.input == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil error")
			}

			if result.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result.Error())
			}
		})
	}
}

func TestEncryptionError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *EncryptionError
		contains []string
	}{
		{
			name: "with chunk number",
			err: &EncryptionError{
				Op:       "encrypt",
				Path:     "/path/to/file.txt",
				ChunkNum: 5,
				Err:      fmt.Errorf("authentication failed"),
			},
			contains: []string{"encrypt", "/path/to/file.txt", "chunk 5", "authentication failed"},
		},
		{
			name: "without chunk number",
			err: &EncryptionError{
				Op:       "decrypt",
				Path:     "/path/to/encrypted.enc",
				ChunkNum: -1,
				Err:      fmt.Errorf("invalid header"),
			},
			contains: []string{"decrypt", "/path/to/encrypted.enc", "invalid header"},
		},
		{
			name: "chunk 0 is valid",
			err: &EncryptionError{
				Op:       "encrypt",
				Path:     "file.dat",
				ChunkNum: 0,
				Err:      errors.New("chunk error"),
			},
			contains: []string{"encrypt", "file.dat", "chunk 0", "chunk error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("expected error message to contain %q, got: %s", substr, result)
				}
			}
		})
	}
}

func TestEncryptionError_Unwrap(t *testing.T) {
	innerErr := fmt.Errorf("inner error")
	encErr := &EncryptionError{
		Op:       "test",
		Path:     "test.txt",
		ChunkNum: -1,
		Err:      innerErr,
	}

	unwrapped := encErr.Unwrap()
	if unwrapped != innerErr {
		t.Errorf("expected unwrapped error to be %v, got %v", innerErr, unwrapped)
	}

	// Test with errors.Is
	if !errors.Is(encErr, innerErr) {
		t.Error("errors.Is should work with EncryptionError")
	}
}

func TestNewEncryptionError(t *testing.T) {
	innerErr := fmt.Errorf("test error")
	err := NewEncryptionError("encrypt", "/path/file.txt", 42, innerErr)

	if err.Op != "encrypt" {
		t.Errorf("expected Op to be 'encrypt', got %q", err.Op)
	}
	if err.Path != "/path/file.txt" {
		t.Errorf("expected Path to be '/path/file.txt', got %q", err.Path)
	}
	if err.ChunkNum != 42 {
		t.Errorf("expected ChunkNum to be 42, got %d", err.ChunkNum)
	}
	if err.Err != innerErr {
		t.Errorf("expected Err to be %v, got %v", innerErr, err.Err)
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name     string
		context  string
		err      error
		expected string
		isNil    bool
	}{
		{
			name:     "nil error",
			context:  "some context",
			err:      nil,
			expected: "",
			isNil:    true,
		},
		{
			name:     "wrap simple error",
			context:  "read file",
			err:      fmt.Errorf("permission denied"),
			expected: "read file: permission denied",
			isNil:    false,
		},
		{
			name:     "wrap with empty context",
			context:  "",
			err:      fmt.Errorf("some error"),
			expected: ": some error",
			isNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WrapError(tt.context, tt.err)

			if tt.isNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected non-nil error")
			}

			if result.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result.Error())
			}

			// Verify unwrapping works
			if !errors.Is(result, tt.err) {
				t.Error("wrapped error should be detectable with errors.Is")
			}
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Verify error constants are not nil and have reasonable messages
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidKey", ErrInvalidKey},
		{"ErrInvalidNonce", ErrInvalidNonce},
		{"ErrChunkSize", ErrChunkSize},
		{"ErrChecksum", ErrChecksum},
		{"ErrContextCanceled", ErrContextCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s should not be nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s should have a non-empty error message", tt.name)
			}
		})
	}
}
