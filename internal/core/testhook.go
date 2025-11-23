//go:build testhooks
// +build testhooks

/*
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package core

// This file intentionally left minimal; the real test helper is provided in
// `test_helpers_testhooks.go`. Keeping this file avoids build surprises on
// some toolchains that prefer a single matching file per feature.
