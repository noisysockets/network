// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

// Package forwarder provides a TCP and UDP session forwarder.
package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/noisysockets/contextio"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/netstack/pkg/waiter"
	"github.com/noisysockets/network"
	"github.com/noisysockets/network/cidrs"
	"github.com/noisysockets/network/internal/util"
	"golang.org/x/sync/semaphore"
)

var _ network.Forwarder = (*Forwarder)(nil)

// ForwarderConfig is the configuration for the network session forwarder.
type ForwarderConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// Maximum number of in-flight TCP connection attempts.
	MaxInFlightTCPConnectionAttempts *int
	// Maximum number of concurrent TCP sessions.
	MaxConcurrentTCP *int
	// Maximum number of concurrent UDP sessions.
	MaxConcurrentUDP *int
	// How long to wait for activity on a UDP session before considering it	dead.
	UDPTimeout *time.Duration
}

// Default values (if not set).
var defaultForwarderConf = ForwarderConfig{
	DeniedDestinations: []netip.Prefix{
		// Deny loopback traffic.
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	},
	MaxInFlightTCPConnectionAttempts: util.PointerTo(16),
	MaxConcurrentTCP:                 util.PointerTo(1024),
	MaxConcurrentUDP:                 util.PointerTo(1024),
	UDPTimeout:                       util.PointerTo(30 * time.Second),
}

// Forwarder is a network session forwarder.
type Forwarder struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	logger              *slog.Logger
	dstNet              network.Network
	tcpForwarder        *tcp.Forwarder
	udpForwarder        *udp.Forwarder
	tcpSessionCounter   *semaphore.Weighted
	udpSessionCounter   *semaphore.Weighted
	udpTimeout          time.Duration
	allowedDestinations *cidrs.TrieMap[struct{}]
	deniedDestinations  *cidrs.TrieMap[struct{}]
}

func New(ctx context.Context, logger *slog.Logger, srcNet, dstNet network.Network, conf *ForwarderConfig) (*Forwarder, error) {
	conf, err := util.ConfigWithDefaults(conf, &defaultForwarderConf)
	if err != nil {
		return nil, fmt.Errorf("failed to populate configuration with defaults: %w", err)
	}

	allowedDestinations := cidrs.NewTrieMap[struct{}]()
	for _, prefix := range conf.AllowedDestinations {
		allowedDestinations.Insert(prefix, struct{}{})
	}

	deniedDestinations := cidrs.NewTrieMap[struct{}]()
	for _, prefix := range conf.DeniedDestinations {
		deniedDestinations.Insert(prefix, struct{}{})
	}

	ctx, cancel := context.WithCancel(ctx)

	fwd := &Forwarder{
		ctx:                 ctx,
		cancel:              cancel,
		logger:              logger,
		dstNet:              dstNet,
		tcpSessionCounter:   semaphore.NewWeighted(int64(*conf.MaxConcurrentTCP)),
		udpSessionCounter:   semaphore.NewWeighted(int64(*conf.MaxConcurrentUDP)),
		udpTimeout:          *conf.UDPTimeout,
		allowedDestinations: allowedDestinations,
		deniedDestinations:  deniedDestinations,
	}

	userspaceNet, ok := srcNet.(*network.UserspaceNetwork)
	if !ok {
		return nil, errors.New("source network must be userspace")
	}

	stack := userspaceNet.Stack()
	fwd.tcpForwarder = tcp.NewForwarder(stack, 0, *conf.MaxInFlightTCPConnectionAttempts, fwd.tcpHandler)
	fwd.udpForwarder = udp.NewForwarder(stack, fwd.udpHandler)

	return fwd, nil
}

// Close closes the forwarder.
func (f *Forwarder) Close() error {
	f.cancel()
	return nil
}

// ValidDestination checks if the destination address is valid for forwarding.
func (f *Forwarder) ValidDestination(addr netip.Addr) bool {
	_, allowed := f.allowedDestinations.Get(addr)
	if allowed {
		if _, denied := f.deniedDestinations.Get(addr); denied {
			allowed = false
		}
	}

	return allowed
}

// TCPProtocolHandler forwards TCP sessions.
func (f *Forwarder) TCPProtocolHandler(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return f.tcpForwarder.HandlePacket(id, pkt)
}

// UDPProtocolHandler forwards UDP sessions.
func (f *Forwarder) UDPProtocolHandler(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	return f.udpForwarder.HandlePacket(id, pkt)
}

// ICMPv4ProtocolHandler forwards ICMPv4 sessions.
func (f *Forwarder) ICMPv4ProtocolHandler(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdr := header.ICMPv4(pkt.TransportHeader().Slice())
	if len(hdr) < header.ICMPv4MinimumSize {
		f.logger.Debug("Dropping invalid ICMPv4 packet")
		return true
	}

	// Don't bother with checksums.

	logger := f.logger.With(
		slog.String("proto", "icmpv4"),
		slog.String("src", id.RemoteAddress.String()),
		slog.String("dst", id.LocalAddress.String()))

	if hdr.Type() == header.ICMPv4Echo {
		logger.Info("Received ICMPv4 echo request")

		// TODO: Forward the packet (eg. shell out to ping)
	} else {
		logger.Debug("Ignoring ICMPv4 packet",
			slog.Int("type", int(hdr.Type())))
	}

	// Ignore other ICMPv4 packets.
	return true
}

// ICMPv6ProtocolHandler forwards ICMPv6 sessions.
func (f *Forwarder) ICMPv6ProtocolHandler(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdr := header.ICMPv6(pkt.TransportHeader().Slice())
	if len(hdr) < header.ICMPv6MinimumSize {
		f.logger.Debug("Dropping invalid ICMPv6 packet")
		return true
	}

	// Don't bother with checksums.

	logger := f.logger.With(
		slog.String("proto", "icmpv6"),
		slog.String("src", id.RemoteAddress.String()),
		slog.String("dst", id.LocalAddress.String()))

	if hdr.Type() == header.ICMPv6EchoRequest {
		logger.Info("Received ICMPv6 echo request")

		// TODO: Forward the packet (eg. shell out to ping)
	} else {
		logger.Debug("Ignoring ICMPv6 packet",
			slog.Int("type", int(hdr.Type())))
	}

	return true
}

func (f *Forwarder) tcpHandler(req *tcp.ForwarderRequest) {
	reqDetails := req.ID()

	srcAddrPort := util.AddrPortFrom(reqDetails.RemoteAddress, reqDetails.RemotePort)
	dstAddrPort := util.AddrPortFrom(reqDetails.LocalAddress, reqDetails.LocalPort)

	logger := f.logger.With(
		slog.String("proto", "tcp"),
		slog.String("src", srcAddrPort.String()),
		slog.String("dst", dstAddrPort.String()))

	if !f.ValidDestination(dstAddrPort.Addr()) {
		logger.Warn("Destination not allowed")
		req.Complete(true)
		return
	}

	go func() {
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		if ok := f.tcpSessionCounter.TryAcquire(1); !ok {
			logger.Warn("Forwarder at capacity, rejecting session")
			req.Complete(true)
			return
		}
		defer f.tcpSessionCounter.Release(1)

		logger.Debug("Forwarding session")
		defer logger.Debug("Session finished")

		var wq waiter.Queue
		ep, tcpipErr := req.CreateEndpoint(&wq)
		if tcpipErr != nil {
			logger.Error("Failed to create local endpoint",
				slog.String("error", tcpipErr.String()))

			req.Complete(true)
			return
		}

		// Cancel the context when the connection is closed.
		waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
		wq.EventRegister(&waitEntry)
		defer wq.EventUnregister(&waitEntry)

		go func() {
			select {
			case <-ctx.Done():
			case <-notifyCh:
				cancel()
			}
		}()

		// Disable Nagle's algorithm.
		ep.SocketOptions().SetDelayOption(true)
		// Enable keep-alive to make detecting dead connections easier.
		ep.SocketOptions().SetKeepAlive(true)

		local := gonet.NewTCPConn(&wq, ep)
		defer local.Close()

		// Connect to the destination.
		remote, err := f.dstNet.DialContext(ctx, "tcp", dstAddrPort.String())
		if err != nil {
			logger.Error("Failed to dial destination", slog.Any("error", err))

			req.Complete(true)
			return
		}
		defer remote.Close()

		// Start forwarding.
		if _, err := contextio.SpliceContext(ctx, local, remote, nil); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("Failed to forward session", slog.Any("error", err))

			req.Complete(true)
			return
		}

		req.Complete(false)
	}()
}

func (f *Forwarder) udpHandler(req *udp.ForwarderRequest) {
	reqDetails := req.ID()

	srcAddrPort := util.AddrPortFrom(reqDetails.RemoteAddress, reqDetails.RemotePort)
	dstAddrPort := util.AddrPortFrom(reqDetails.LocalAddress, reqDetails.LocalPort)

	logger := f.logger.With(
		slog.String("proto", "udp"),
		slog.String("src", srcAddrPort.String()),
		slog.String("dst", dstAddrPort.String()))

	if !f.ValidDestination(dstAddrPort.Addr()) {
		logger.Warn("Destination not allowed")
		return
	}

	if ok := f.udpSessionCounter.TryAcquire(1); !ok {
		logger.Warn("Forwarder at capacity, rejecting session")
		return
	}

	// Create endpoint as quickly as possible to avoid UDP race conditions, when
	// multiple frames are in flight.
	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		logger.Error("Failed to create local endpoint",
			slog.String("error", tcpipErr.String()))

		return
	}

	go func() {
		defer f.udpSessionCounter.Release(1)

		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		logger.Debug("Forwarding session")
		defer logger.Debug("Session finished")

		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()

		remote, err := f.dstNet.DialContext(ctx, "udp", dstAddrPort.String())
		if err != nil {
			logger.Error("Failed to dial destination", slog.Any("error", err))

			return
		}
		defer remote.Close()

		if _, err := contextio.SpliceContext(ctx, local, remote, &f.udpTimeout); err != nil &&
			!(errors.Is(err, context.Canceled) || errors.Is(err, os.ErrDeadlineExceeded)) {
			logger.Error("Failed to forward session", slog.Any("error", err))

			return
		}
	}()
}
