//go:build testhooks
// +build testhooks

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

// SetEncryptorChunkCounter sets the internal chunk counter of an Encryptor.
// Test-only helper compiled with the 'testhooks' build tag.
func SetEncryptorChunkCounter(e *Encryptor, v uint32) {
	if e == nil {
		return
	}
	e.startChunkCounter = v
}
