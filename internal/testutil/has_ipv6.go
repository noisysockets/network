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
	"net"
	"testing"
	"time"
)

// EnsureIPv6 skips the test if the system does not have IPv6 connectivity.
func EnsureIPv6(t *testing.T) {
	// Attempt to connect to Google's public DNS server over IPv6.
	conn, err := net.DialTimeout("tcp", "[2001:4860:4860::8888]:53", 5*time.Second)
	if err != nil {
		t.Skip("IPv6 is not supported")
		return
	}
	_ = conn.Close()
}
