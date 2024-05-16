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
	"context"
	stdnet "net"
	"os"
)

var (
	// Ensure that HostNetwork implements Network interface.
	_ Network = (*HostNetwork)(nil)
)

type HostNetwork struct{}

// Host returns a Network implementation that uses the standard library's network operations.
func Host() *HostNetwork {
	return &HostNetwork{}
}

func (net *HostNetwork) Close() error {
	return nil
}

func (net *HostNetwork) Hostname() (string, error) {
	return os.Hostname()
}

func (net *HostNetwork) InterfaceAddrs() ([]stdnet.Addr, error) {
	return stdnet.InterfaceAddrs()
}

func (net *HostNetwork) LookupHost(host string) ([]string, error) {
	return stdnet.LookupHost(host)
}

func (net *HostNetwork) LookupHostContext(ctx context.Context, host string) ([]string, error) {
	return stdnet.DefaultResolver.LookupHost(ctx, host)
}

func (net *HostNetwork) Dial(network, address string) (stdnet.Conn, error) {
	return stdnet.Dial(network, address)
}

func (net *HostNetwork) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	var d stdnet.Dialer
	return d.DialContext(ctx, network, address)
}

func (net *HostNetwork) Listen(network, address string) (stdnet.Listener, error) {
	return stdnet.Listen(network, address)
}

func (net *HostNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	return stdnet.ListenPacket(network, address)
}
