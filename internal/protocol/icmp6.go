// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package protocol

import (
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/icmp"
)

const (
	// ForwardedICMPv6ProtocolNumber is the protocol number used to indicate
	// that the packet is an ICMPv6 packet that needs to be forwarded.
	ForwardedICMPv6ProtocolNumber = 254
)

// forwardedICMPv6Protocol is a hack to allow intercepting and forwarding ICMP
// packets with netstack.
type forwardedICMPv6Protocol struct {
	stack.TransportProtocol
}

func NewProtocolForwardedICMPv6(s *stack.Stack) stack.TransportProtocol {
	return &forwardedICMPv6Protocol{
		TransportProtocol: icmp.NewProtocol6(s),
	}
}

func (p *forwardedICMPv6Protocol) Number() tcpip.TransportProtocolNumber {
	return ForwardedICMPv6ProtocolNumber
}
