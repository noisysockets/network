// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package forwarder_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/network"
	"github.com/noisysockets/network/forwarder"
	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestForwarder(t *testing.T) {
	logger := slogt.New(t)

	// Create what is essentially a userspace veth pair.
	nicA, nicB := network.Pipe(1500, 16)
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
	})

	ctx := context.Background()

	netA, err := network.Userspace(ctx, logger.With(slog.String("net", "a")), nicA, &network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netA.Close()
	})

	// Forward out to the host network from net A.
	fwd := forwarder.New(ctx, logger, network.Host(), &forwarder.ForwarderConfig{
		AllowedDestinations: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		// Deny localhost traffic.
		DeniedDestinations: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		},
	})
	t.Cleanup(func() {
		_ = fwd.Close()
	})

	err = netA.EnableForwarding(fwd)
	require.NoError(t, err)

	netB, err := network.Userspace(ctx, logger.With(slog.String("net", "b")), nicB, &network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		ResolverFactory: func(dialContext network.DialContextFunc) resolver.Resolver {
			// Cloudflare DNS over UDP.
			return resolver.Chain(resolver.IP(), resolver.DNS(&resolver.DNSResolverConfig{
				Protocol:    resolver.ProtocolUDP,
				Servers:     []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
				Timeout:     5 * time.Second,
				DialContext: dialContext,
			}))
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netB.Close()
	})

	// Create a http client that will dial out through our network.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = netB.DialContext

	client := *http.DefaultClient
	client.Transport = transport

	// Make a request to a public address to verify that our forwarder is working.
	resp, err := client.Get("https://icanhazip.com")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Make sure the response body is a valid IP address.
	_, err = netip.ParseAddr(strings.TrimSpace(string(body)))
	require.NoError(t, err)
}
