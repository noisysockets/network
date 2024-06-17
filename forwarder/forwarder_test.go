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

	"github.com/noisysockets/util/ptr"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/network"
	"github.com/noisysockets/network/forwarder"
	"github.com/noisysockets/network/internal/testutil"
	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
)

func TestForwarder(t *testing.T) {
	logger := slogt.New(t)

	// Create what is essentially a userspace veth pair.
	nicA, nicB := network.Pipe(nil)
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
	})

	ctx := context.Background()

	netA, err := network.Userspace(ctx, logger.With(slog.String("net", "a")), nicA, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
			netip.MustParsePrefix("fdff:7061:ac89::1/128"),
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netA.Close()
	})

	// Forward out to the host network from net A.
	fwd, err := forwarder.New(ctx, logger, netA, network.Host(), &forwarder.ForwarderConfig{
		AllowedDestinations: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
		EnableNAT64: ptr.To(false),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = fwd.Close()
	})

	err = netA.EnableForwarding(fwd)
	require.NoError(t, err)

	netB, err := network.Userspace(ctx, logger.With(slog.String("net", "b")), nicB, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.2/32"),
			netip.MustParsePrefix("fdff:7061:ac89::2/128"),
		},
		ResolverFactory: func(dialContext network.DialContextFunc) (resolver.Resolver, error) {
			return resolver.System(nil)
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netB.Close()
	})

	t.Run("TCP", func(t *testing.T) {
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
	})

	t.Run("UDP", func(t *testing.T) {
		// An example.com A record query.
		dnsQuery := []byte{
			0xab, 0xcd, // Transaction ID
			0x01, 0x00, // Flags: standard query with recursion desired.
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
			0x03, 'c', 'o', 'm', // "com"
			0x00,       // End of domain name
			0x00, 0x01, // Type: A (Host address)
			0x00, 0x01, // Class: IN (Internet)
		}

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		conn, err := netB.DialContext(ctx, "udp", "8.8.8.8:53")
		require.NoError(t, err)

		// Send the query.
		_, err = conn.Write(dnsQuery)
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, conn.Close())
		})

		// Read the response.
		dnsResponse := make([]byte, 512)
		_, err = conn.Read(dnsResponse)
		require.NoError(t, err)

		// Verify transaction ID.
		require.Equal(t, dnsQuery[:2], dnsResponse[:2])

		// Verify that we got a NOERROR response.
		require.Equal(t, byte(0), dnsResponse[3]&0x0F)
	})

	t.Run("ICMPv4", func(t *testing.T) {
		testutil.EnsureNotGitHubActions(t)

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		err := netB.Ping(ctx, "ip4", "8.8.8.8")
		require.NoError(t, err)
	})

	t.Run("ICMPv6", func(t *testing.T) {
		testutil.EnsureNotGitHubActions(t)
		testutil.EnsureIPv6(t)

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		err := netB.Ping(ctx, "ip6", "2001:4860:4860::8888")
		require.NoError(t, err)
	})
}

func TestForwarderWithNAT64(t *testing.T) {
	testutil.EnsureIPv6(t)

	logger := slogt.New(t)

	// Create what is essentially a userspace veth pair.
	nicA, nicB := network.Pipe(nil)
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
	})

	ctx := context.Background()

	netA, err := network.Userspace(ctx, logger.With(slog.String("net", "a")), nicA, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("fdff:7061:ac89::1/128"),
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netA.Close()
	})

	// Forward out to the host network from net A.
	fwd, err := forwarder.New(ctx, logger, netA, network.Host(), &forwarder.ForwarderConfig{
		AllowedDestinations: []netip.Prefix{
			netip.MustParsePrefix("::/0"),
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = fwd.Close()
	})

	err = netA.EnableForwarding(fwd)
	require.NoError(t, err)

	netB, err := network.Userspace(ctx, logger.With(slog.String("net", "b")), nicB, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("fdff:7061:ac89::2/128"),
		},
		ResolverFactory: func(dialContext network.DialContextFunc) (resolver.Resolver, error) {
			// Googles public DNS64 resolver.
			return resolver.DNS(resolver.DNSResolverConfig{
				Server: netip.AddrPortFrom(netip.MustParseAddr("2001:4860:4860::6464"), 53),
			}), nil
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

	t.Run("IPv4 Translation", func(t *testing.T) {
		// Make a request to a public ipv4 address to verify that our forwarder is working.
		resp, err := client.Get("https://ipv4.icanhazip.com")
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = resp.Body.Close()
		})

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		// Make sure the response body is a valid IPv4 address.
		addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		require.NoError(t, err)

		require.True(t, addr.Unmap().Is4())
	})

	t.Run("ICMPv4 Translation", func(t *testing.T) {
		testutil.EnsureNotGitHubActions(t)

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		err := netB.Ping(ctx, "ip6", "ipv4.icanhazip.com")
		require.NoError(t, err)
	})
}
