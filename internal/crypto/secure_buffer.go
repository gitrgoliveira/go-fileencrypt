/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package crypto

import (
	"sync"

	"github.com/gitrgoliveira/go-fileencrypt/secure"
)

// SecureBuffer provides memory-safe storage for sensitive key material.
type SecureBuffer struct {
	buf    []byte
	mu     sync.Mutex
	zeroed bool
	unlock func()
}

// NewSecureBufferFromBytes creates a SecureBuffer from a byte slice.
// It attempts to lock the memory to prevent swapping (best effort).
func NewSecureBufferFromBytes(b []byte) (*SecureBuffer, error) {
	buf := make([]byte, len(b))
	copy(buf, b)

	// Attempt to lock memory (best effort, errors are logged but don't fail)
	unlock := func() {}
	if err := secure.LockMemory(buf); err == nil {
		unlock = func() {
			_ = secure.UnlockMemory(buf)
		}
	}

	return &SecureBuffer{
		buf:    buf,
		unlock: unlock,
	}, nil
}

// Data returns the buffer contents.
func (s *SecureBuffer) Data() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf
}

// Destroy zeroes the buffer, unlocks memory, and marks it destroyed.
func (s *SecureBuffer) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.zeroed {
		// Securely zero the buffer
		secure.Zero(s.buf)
		s.zeroed = true

		// Unlock memory if it was locked
		if s.unlock != nil {
			s.unlock()
		}
	}
}
