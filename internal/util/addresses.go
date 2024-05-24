// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import (
	"net/netip"

	"github.com/noisysockets/netstack/pkg/tcpip"
)

// AddrPortFrom returns a netip.AddrPort from a tcpip.Address and a port.
func AddrPortFrom(addr tcpip.Address, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(AddrFrom(addr), port)
}

// AddrFrom returns a netip.Addr from a tcpip.Address.
func AddrFrom(addr tcpip.Address) (netipAddr netip.Addr) {
	netipAddr, _ = netip.AddrFromSlice(addr.AsSlice())
	return netipAddr.Unmap()
}
