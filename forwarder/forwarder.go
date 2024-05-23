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
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/noisysockets/contextio"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/netstack/pkg/waiter"
	"github.com/noisysockets/network"
	"github.com/noisysockets/network/cidrs"
	"golang.org/x/sync/semaphore"
)

const (
	defaultMaxConcurrentTCP = 1024
	defaultMaxConcurrentUDP = 1024
	defaultUDPTimeout       = 30 * time.Second
)

var (
	_ network.Forwarder = (*Forwarder)(nil)
)

// ForwarderConfig is the configuration for the TCP and UDP forwarder.
type ForwarderConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// Maximum number of concurrent TCP sessions.
	MaxConcurrentTCP *int
	// Maximum number of concurrent UDP sessions.
	MaxConcurrentUDP *int
	// How long to wait for activity on a UDP session before considering it	dead.
	UDPTimeout *time.Duration
}

// Forwarder forwards TCP and UDP sessions to the provided network.
type Forwarder struct {
	logger              *slog.Logger
	net                 network.Network
	ctx                 context.Context
	cancel              context.CancelFunc
	tcpSessionSem       *semaphore.Weighted
	udpSessionSem       *semaphore.Weighted
	udpTimeout          time.Duration
	allowedDestinations *cidrs.TrieMap[struct{}]
	deniedDestinations  *cidrs.TrieMap[struct{}]
}

// New creates a new TCP and UDP forwarder.
func New(ctx context.Context, logger *slog.Logger, net network.Network, conf *ForwarderConfig) *Forwarder {
	if conf == nil {
		conf = &ForwarderConfig{}
	}

	maxConcurrentTCP := defaultMaxConcurrentTCP
	if conf.MaxConcurrentTCP != nil {
		maxConcurrentTCP = *conf.MaxConcurrentTCP
	}

	maxConcurrentUDP := defaultMaxConcurrentUDP
	if conf.MaxConcurrentUDP != nil {
		maxConcurrentUDP = *conf.MaxConcurrentUDP
	}

	udpTimeout := defaultUDPTimeout
	if conf.UDPTimeout != nil {
		udpTimeout = *conf.UDPTimeout
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

	return &Forwarder{
		logger:              logger,
		net:                 net,
		ctx:                 ctx,
		cancel:              cancel,
		tcpSessionSem:       semaphore.NewWeighted(int64(maxConcurrentTCP)),
		udpSessionSem:       semaphore.NewWeighted(int64(maxConcurrentUDP)),
		udpTimeout:          udpTimeout,
		allowedDestinations: allowedDestinations,
		deniedDestinations:  deniedDestinations,
	}
}

// Close closes the forwarder.
func (f *Forwarder) Close() error {
	f.cancel()
	return nil
}

// TCPProtocolHandler forwards TCP sessions.
func (f *Forwarder) TCPProtocolHandler(req *tcp.ForwarderRequest) {
	reqDetails := req.ID()

	srcAddrPort := addrPortFrom(reqDetails.RemoteAddress, reqDetails.RemotePort)
	dstAddrPort := addrPortFrom(reqDetails.LocalAddress, reqDetails.LocalPort)

	logger := f.logger.With(
		slog.String("proto", "tcp"),
		slog.String("src", srcAddrPort.String()),
		slog.String("dst", dstAddrPort.String()))

	_, allowed := f.allowedDestinations.Get(dstAddrPort.Addr())
	if allowed {
		if _, denied := f.deniedDestinations.Get(dstAddrPort.Addr()); denied {
			allowed = false
		}
	}

	if !allowed {
		logger.Warn("Destination not allowed")
		req.Complete(true)
		return
	}

	go func() {
		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		if ok := f.tcpSessionSem.TryAcquire(1); !ok {
			logger.Warn("Forwarder at capacity, rejecting session")
			req.Complete(true)
			return
		}
		defer f.tcpSessionSem.Release(1)

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
		remote, err := f.net.DialContext(ctx, "tcp", dstAddrPort.String())
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

// UDPProtocolHandler forwards UDP sessions.
func (f *Forwarder) UDPProtocolHandler(req *udp.ForwarderRequest) {
	reqDetails := req.ID()

	srcAddrPort := addrPortFrom(reqDetails.RemoteAddress, reqDetails.RemotePort)
	dstAddrPort := addrPortFrom(reqDetails.LocalAddress, reqDetails.LocalPort)

	logger := f.logger.With(
		slog.String("proto", "udp"),
		slog.String("src", srcAddrPort.String()),
		slog.String("dst", dstAddrPort.String()))

	_, allowed := f.allowedDestinations.Get(dstAddrPort.Addr())
	if allowed {
		if _, denied := f.deniedDestinations.Get(dstAddrPort.Addr()); denied {
			allowed = false
		}
	}

	if !allowed {
		logger.Warn("Destination not allowed")
		return
	}

	if ok := f.udpSessionSem.TryAcquire(1); !ok {
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
		defer f.udpSessionSem.Release(1)

		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		logger.Debug("Forwarding session")
		defer logger.Debug("Session finished")

		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()

		remote, err := f.net.DialContext(ctx, "udp", dstAddrPort.String())
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

func addrPortFrom(addr tcpip.Address, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(addrFrom(addr), port)
}

func addrFrom(addr tcpip.Address) (netipAddr netip.Addr) {
	netipAddr, _ = netip.AddrFromSlice(addr.AsSlice())
	return netipAddr.Unmap()
}
