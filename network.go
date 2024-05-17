// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Package network provides a host independent abstraction for network operations.
package network

import (
	"context"
	"errors"
	"io"
	stdnet "net"
)

var (
	ErrInvalidPort           = errors.New("invalid port")
	ErrMissingAddress        = errors.New("missing address")
	ErrNoSuitableAddress     = errors.New("no suitable address found")
	ErrUnexpectedAddressType = errors.New("unexpected address type")
)

// Network is an interface that abstracts the standard library's network operations.
type Network interface {
	io.Closer
	// Hostname returns the hostname of the local machine.
	Hostname() (string, error)
	// InterfaceAddrs returns a list of the network interfaces addresses.
	InterfaceAddrs() ([]stdnet.Addr, error)
	// LookupHost looks up the IP addresses for the given host.
	LookupHost(host string) ([]string, error)
	// LookupHostContext looks up the IP addresses for the given host.
	LookupHostContext(ctx context.Context, host string) ([]string, error)
	// Dial connects to the address on the named network.
	// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only), "udp", "udp4" (IPv4-only), "udp6" (IPv6-only).
	Dial(network, address string) (stdnet.Conn, error)
	// DialContext connects to the address on the named network using the provided context.
	DialContext(ctx context.Context, network, address string) (stdnet.Conn, error)
	// Listen listens for incoming connections on the network address.
	// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only).
	// If the address is an empty string, Listen listens on all available addresses.
	Listen(network, address string) (stdnet.Listener, error)
	// ListenPacket listens for incoming packets addressed to the local address.
	// Known networks are "udp", "udp4" (IPv4-only), "udp6" (IPv6-only).
	ListenPacket(network, address string) (stdnet.PacketConn, error)
}
