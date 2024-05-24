// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package target

import (
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
)

var _ stack.Target = (*rewriteTransportProtocolTarget)(nil)

type rewriteTransportProtocolTarget struct {
	transportProtocolNumber tcpip.TransportProtocolNumber
}

// RewriteTransportProtocol modifies the transport protocol number of the packet
// to the given value, and accepts the packet.
func RewriteTransportProtocol(transportProtocolNumber tcpip.TransportProtocolNumber) stack.Target {
	return &rewriteTransportProtocolTarget{transportProtocolNumber: transportProtocolNumber}
}

func (t *rewriteTransportProtocolTarget) Action(pkt *stack.PacketBuffer, _ stack.Hook, _ *stack.Route, _ stack.AddressableEndpoint) (verdict stack.RuleVerdict, jumpTo int) {
	pkt.TransportProtocolNumber = t.transportProtocolNumber

	hdr := pkt.NetworkHeader().Slice()

	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if len(hdr) < header.IPv4MinimumSize {
			// Invalid packet.
			return stack.RuleDrop, 0
		}

		// The protocol field is at offset 9.
		hdr[9] = uint8(t.transportProtocolNumber)
	case header.IPv6ProtocolNumber:
		if len(hdr) < header.IPv6MinimumSize {
			// Invalid packet.
			return stack.RuleDrop, 0
		}

		// The next header field is at offset 6.
		hdr[6] = uint8(t.transportProtocolNumber)
	default:
		// Unsupported protocol.
		return stack.RuleDrop, 0
	}

	return stack.RuleAccept, 0
}
