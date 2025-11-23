//go:build unix

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package fileencrypt_test

import "syscall"

// mkfifo creates a named pipe (FIFO) on Unix systems
func mkfifo(path string) error {
	return syscall.Mkfifo(path, 0666)
}
