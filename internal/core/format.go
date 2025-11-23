/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

// format.go: File format constants and algorithm ID support for go-fileencrypt
package core

const (
	// MagicBytes is the file signature "GFE" (Go File Encrypt).
	MagicBytes = "GFE"
	// Version is the current file format version (1).
	Version = 1
	// NonceSize is the size of the nonce for AES-GCM.
	NonceSize = 12
	// HeaderSize is the total size of the file header.
	// File format: [3 bytes magic][1 byte version][12 bytes nonce][8 bytes file size][chunks...]
	HeaderSize = len(MagicBytes) + 1 + NonceSize + 8
	// MaxChunkSize is the maximum size for a single chunk of data.
	MaxChunkSize = 10 * 1024 * 1024
)
