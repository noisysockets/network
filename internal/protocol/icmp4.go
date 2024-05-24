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
	// ForwardedICMPv4ProtocolNumber is the protocol number used to indicate
	// that the packet is an ICMPv4 packet that needs to be forwarded.
	ForwardedICMPv4ProtocolNumber = 253
)

// forwardedICMPv4Protocol is a hack to allow intercepting and forwarding ICMP
// packets with netstack.
type forwardedICMPv4Protocol struct {
	stack.TransportProtocol
}

func NewProtocolForwardedICMPv4(s *stack.Stack) stack.TransportProtocol {
	return &forwardedICMPv4Protocol{
		TransportProtocol: icmp.NewProtocol4(s),
	}
}

func (p *forwardedICMPv4Protocol) Number() tcpip.TransportProtocolNumber {
	return ForwardedICMPv4ProtocolNumber
}
