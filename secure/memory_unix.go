//go:build unix || darwin

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package secure

import (
	"syscall"
)

// LockMemory uses mlock for Unix/macOS
func LockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Mlock(b)
}

// UnlockMemory uses munlock for Unix/macOS
func UnlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Munlock(b)
}
