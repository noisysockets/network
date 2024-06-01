// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package matcher

import (
	"net/netip"

	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netutil/cidrs"
	"github.com/noisysockets/network/internal/util"
)

var _ stack.Matcher = (*destinationMatcher)(nil)

type destinationMatcher struct {
	prefixes *cidrs.TrieMap[struct{}]
}

func Destination(prefixes *cidrs.TrieMap[struct{}]) *destinationMatcher {
	return &destinationMatcher{prefixes: prefixes}
}

func (m *destinationMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (matches bool, hotdrop bool) {
	hdr := pkt.NetworkHeader().Slice()

	var dstAddr netip.Addr
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if len(hdr) < header.IPv4MinimumSize {
			// Invalid packet.
			return false, true
		}

		ipHdr := header.IPv4(hdr)
		dstAddr = util.AddrFrom(ipHdr.DestinationAddress())
	case header.IPv6ProtocolNumber:
		if len(hdr) < header.IPv6MinimumSize {
			// Invalid packet.
			return false, true
		}

		ipHdr := header.IPv6(hdr)
		dstAddr = util.AddrFrom(ipHdr.DestinationAddress())
	default:
		// Unsupported protocol.
		return false, true
	}

	if _, ok := m.prefixes.Get(dstAddr); ok {
		return true, false
	}

	return false, false
}
