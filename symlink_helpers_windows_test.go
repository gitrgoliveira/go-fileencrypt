//go:build windows

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package fileencrypt_test

import "errors"

// mkfifo is not supported on Windows
func mkfifo(path string) error {
	return errors.New("named pipes not supported on Windows")
}
