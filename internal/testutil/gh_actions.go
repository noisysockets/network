// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package testutil

import (
	"os"
	"testing"
)

// EnsureNotGitHubActions skips the test if it is running in a GitHub Actions environment.
// This is important for tests that require ICMP connectivity, as GitHub Actions
// drops outgoing ICMP packets.
func EnsureNotGitHubActions(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Skip("GitHub Actions environment detected")
	}
}
