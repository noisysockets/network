// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import (
	"errors"
	"strings"

	"github.com/noisysockets/netstack/pkg/tcpip"
)

var (
	ErrInvalidPort           = errors.New("invalid port")
	ErrMissingAddress        = errors.New("missing address")
	ErrNoSuitableAddress     = errors.New("no suitable address found")
	ErrUnexpectedAddressType = errors.New("unexpected address type")
)

// IsStackClosed checks if the error is due to the network stack being closed.
// This is relevant to errors returned by the userspace network stack.
func IsStackClosed(err error) bool {
	return strings.Contains(err.Error(), (&tcpip.ErrInvalidEndpointState{}).String())
}
