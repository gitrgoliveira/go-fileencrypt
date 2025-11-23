/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package secure

import (
	"crypto/subtle"
)

// Zero securely zeroes a byte slice using constant-time operations
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Use subtle.ConstantTimeCompare to ensure the compiler doesn't optimize away the zeroing
	_ = subtle.ConstantTimeCompare(b, make([]byte, len(b)))
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
