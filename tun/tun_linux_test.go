//go:build linux

// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	stdnet "net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/neilotoole/slogt"
	"github.com/noisysockets/network"
	"github.com/noisysockets/pinger"
	"github.com/noisysockets/resolver"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestTunInterface(t *testing.T) {
	logger := slogt.New(t)

	packetPool := network.NewPacketPool(0, false)

	nicName := fmt.Sprintf("nsh%d", os.Getpid())

	ctx := context.Background()
	nic, err := Create(ctx, logger, nicName, &Configuration{
		PacketPool: packetPool,
	})
	require.NoError(t, err)

	// Setup nic.
	link, err := netlink.LinkByName(nicName)
	require.NoError(t, err)

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &stdnet.IPNet{
			IP:   stdnet.IPv4(100, 64, 0, 2),
			Mask: stdnet.CIDRMask(10, 32),
		},
	})
	require.NoError(t, err)

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &stdnet.IPNet{
			IP:   stdnet.ParseIP("fdff:7061:ac89::2"),
			Mask: stdnet.CIDRMask(64, 128),
		},
	})
	require.NoError(t, err)

	net, err := network.Userspace(ctx, logger, nic, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
			netip.MustParsePrefix("fdff:7061:ac89::1/128"),
		},
		PacketPool:        packetPool,
		PacketWriteOffset: VirtioNetHdrLen,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, net.Close())
	})

	serverCtx, serverCtxCancel := context.WithCancel(ctx)
	t.Cleanup(serverCtxCancel)

	go func() {
		if err := runWebServer(serverCtx, logger, net); err != nil {
			logger.Error("Failed to run web server", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	go func() {
		if err := runDNSServer(serverCtx, logger, net); err != nil {
			logger.Error("Failed to run dns server", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	// Wait for the servers to start.
	time.Sleep(1 * time.Second)

	// Run tests in parallel.
	t.Parallel()

	// Send a whole bunch of traffic to the servers.
	const nRequests = 1000

	t.Run("tcp4", func(t *testing.T) {
		client := http.DefaultClient

		for i := 0; i < nRequests; i++ {
			req, err := http.NewRequestWithContext(ctx, "GET", "http://100.64.0.1", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)

			require.Equal(t, "Hello, World!", string(body))
		}
	})

	t.Run("tcp6", func(t *testing.T) {
		client := http.DefaultClient

		for i := 0; i < nRequests; i++ {
			req, err := http.NewRequestWithContext(ctx, "GET", "http://[fdff:7061:ac89::1]", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)

			require.Equal(t, "Hello, World!", string(body))
		}
	})

	t.Run("udp4", func(t *testing.T) {
		res := resolver.DNS(resolver.DNSResolverConfig{
			Server: netip.MustParseAddrPort("100.64.0.1:53"),
		})

		for i := 0; i < nRequests; i++ {
			addrs, err := res.LookupNetIP(ctx, "ip4", "example.com")
			require.NoError(t, err)

			require.Len(t, addrs, 1)
			require.Equal(t, "100.64.0.1", addrs[0].String())
		}
	})

	t.Run("udp6", func(t *testing.T) {
		res := resolver.DNS(resolver.DNSResolverConfig{
			Server: netip.MustParseAddrPort("[fdff:7061:ac89::1]:53"),
		})

		for i := 0; i < nRequests; i++ {
			addrs, err := res.LookupNetIP(ctx, "ip6", "example.com")
			require.NoError(t, err)

			require.Len(t, addrs, 1)
			require.Equal(t, "fdff:7061:ac89::1", addrs[0].String())
		}
	})

	t.Run("icmp4", func(t *testing.T) {
		p := pinger.New()

		for i := 0; i < nRequests; i++ {
			err := p.Ping(ctx, "ip4", "100.64.0.1")
			require.NoError(t, err)
		}
	})

	t.Run("icmp6", func(t *testing.T) {
		p := pinger.New()

		for i := 0; i < nRequests; i++ {
			err := p.Ping(ctx, "ip6", "fdff:7061:ac89::1")
			require.NoError(t, err)
		}
	})
}

func runWebServer(ctx context.Context, logger *slog.Logger, net network.Network) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello, World!"))
	})

	server := &http.Server{
		BaseContext: func(listener stdnet.Listener) context.Context { return ctx },
		Handler:     mux,
	}

	lis, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		<-ctx.Done()

		logger.Info("Shutting down server")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Failed to shutdown server", slog.Any("error", err))
		}
	}()

	if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}

func runDNSServer(ctx context.Context, logger *slog.Logger, net network.Network) error {
	mux := dns.NewServeMux()

	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := &dns.Msg{}
		msg.SetReply(r)

		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: stdnet.ParseIP("100.64.0.1"),
				})
			case dns.TypeAAAA:
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
					},
					AAAA: stdnet.ParseIP("fdff:7061:ac89::1"),
				})
			default:
				msg.SetRcode(r, dns.RcodeNameError)
			}
		}

		if err := w.WriteMsg(msg); err != nil {
			logger.Error("Failed to write dns response", slog.Any("error", err))
		}
	})

	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	logger.Info("Listening for dns requests", slog.Any("address", pc.LocalAddr()))

	srv := &dns.Server{
		Net:        "udp",
		Handler:    mux,
		PacketConn: pc,
	}

	go func() {
		<-ctx.Done()

		logger.Info("Shutting down server")

		if err := srv.Shutdown(); err != nil {
			logger.Error("Failed to shutdown server", slog.Any("error", err))
		}
	}()

	return srv.ActivateAndServe()
}
