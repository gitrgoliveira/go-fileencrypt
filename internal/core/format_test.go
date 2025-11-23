/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

import (
	"testing"
)

func TestFormatConstants(t *testing.T) {
	if NonceSize != 12 {
		t.Fatalf("unexpected NonceSize: %d", NonceSize)
	}
	if HeaderSize != len(MagicBytes)+1+NonceSize+8 {
		t.Fatalf("unexpected HeaderSize: %d", HeaderSize)
	}
	if MaxChunkSize <= 0 {
		t.Fatalf("MaxChunkSize must be positive")
	}
}
