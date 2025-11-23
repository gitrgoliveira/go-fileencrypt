//go:build windows

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package secure

// LockMemory is a no-op on Windows
func LockMemory(b []byte) error {
	return nil
}

// UnlockMemory is a no-op on Windows
func UnlockMemory(b []byte) error {
	return nil
}
