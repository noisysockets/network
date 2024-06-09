// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from gVisor,
 *
 * Copyright 2018 The gVisor Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package forwarder provides a network session forwarder.
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
	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/checksum"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv6"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/icmp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/netstack/pkg/waiter"
	"github.com/noisysockets/netutil/defaults"
	"github.com/noisysockets/netutil/ptr"
	"github.com/noisysockets/netutil/triemap"
	"github.com/noisysockets/network"
	"github.com/noisysockets/network/internal/util"
)

var _ network.Forwarder = (*Forwarder)(nil)

// ForwarderConfig is the configuration for the network session forwarder.
type ForwarderConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// Maximum number of in-flight TCP connections.
	MaxInFlightTCPConnections *int
	// How long to wait for activity on a UDP session before considering it	dead.
	UDPIdleTimeout *time.Duration
	// How long to wait for an ICMP echo reply before considering it timed out.
	PingTimeout *time.Duration
	// Enable NAT64.
	EnableNAT64 *bool
	// NAT64 prefix.
	NAT64Prefix *netip.Prefix
}

// Default values (if not set).
var defaultForwarderConf = ForwarderConfig{
	DeniedDestinations: []netip.Prefix{
		// Deny loopback traffic.
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	},
	MaxInFlightTCPConnections: ptr.To(2048), // TODO: tune this.
	UDPIdleTimeout:            ptr.To(30 * time.Second),
	PingTimeout:               ptr.To(30 * time.Second),
	EnableNAT64:               ptr.To(true),
	NAT64Prefix:               ptr.To(netip.MustParsePrefix("64:ff9b::/96")),
}

// Forwarder is a network session forwarder.
type Forwarder struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	logger              *slog.Logger
	srcStack            *stack.Stack
	dstNet              network.Network
	tcpForwarder        *tcp.Forwarder
	udpForwarder        *udp.Forwarder
	allowedDestinations *triemap.TrieMap[struct{}]
	deniedDestinations  *triemap.TrieMap[struct{}]
	udpIdleTimeout      time.Duration
	pingTimeout         time.Duration
	enableNAT64         bool
	nat64Prefix         netip.Prefix
}

func New(ctx context.Context, logger *slog.Logger, srcNet, dstNet network.Network, conf *ForwarderConfig) (*Forwarder, error) {
	conf, err := defaults.WithDefaults(conf, &defaultForwarderConf)
	if err != nil {
		return nil, fmt.Errorf("failed to populate configuration with defaults: %w", err)
	}

	userspaceNet, ok := srcNet.(*network.UserspaceNetwork)
	if !ok {
		return nil, errors.New("expected userspace source network")
	}

	allowedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.AllowedDestinations {
		allowedDestinations.Insert(prefix, struct{}{})
	}

	deniedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.DeniedDestinations {
		deniedDestinations.Insert(prefix, struct{}{})
	}

	ctx, cancel := context.WithCancel(ctx)

	fwd := &Forwarder{
		ctx:                 ctx,
		cancel:              cancel,
		logger:              logger,
		srcStack:            userspaceNet.Stack(),
		dstNet:              dstNet,
		allowedDestinations: allowedDestinations,
		deniedDestinations:  deniedDestinations,
		udpIdleTimeout:      *conf.UDPIdleTimeout,
		pingTimeout:         *conf.PingTimeout,
		enableNAT64:         *conf.EnableNAT64,
		nat64Prefix:         *conf.NAT64Prefix,
	}

	fwd.tcpForwarder = tcp.NewForwarder(fwd.srcStack, 0, *conf.MaxInFlightTCPConnections, fwd.tcpHandler)
	fwd.udpForwarder = udp.NewForwarder(fwd.srcStack, fwd.udpHandler)

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
	go func() {
		defer pkt.DecRef()

		ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
		if len(ipHdr) < header.IPv4MinimumSize {
			f.logger.Debug("Dropping invalid IPv4 packet")
			return
		}

		// Fix up our rewritten protocol number.
		// See: rewrite_transport_protocol.go
		ipHdr[9] = uint8(icmp.ProtocolNumber4)

		hdr := header.ICMPv4(pkt.TransportHeader().Slice())
		if len(hdr) < header.ICMPv4MinimumSize {
			f.logger.Debug("Dropping invalid ICMPv4 packet")
			return
		}

		// checksums?

		logger := f.logger.With(
			slog.String("proto", "icmp4"),
			slog.String("src", id.RemoteAddress.String()),
			slog.String("dst", id.LocalAddress.String()))

		defer logger.Debug("Session finished")

		if hdr.Type() == header.ICMPv4Echo {
			logger.Info("Forwarding echo request")

			ctx, cancel := context.WithTimeout(f.ctx, f.pingTimeout)
			defer cancel()

			dstAddr := util.AddrFrom(id.LocalAddress)

			if err := f.dstNet.Ping(ctx, "ip4", dstAddr.String()); err != nil {
				logger.Debug("Failed to ping destination", slog.Any("error", err))
				// TODO: if the destination is unreachable, send an ICMPv4 unreachable message.
				return
			}

			f.logger.Debug("Sending ICMPv4 echo reply")

			if err := f.sendICMPv4EchoReply(pkt); err != nil {
				logger.Warn("Failed to send echo reply", slog.Any("error", err))
			}
		} else {
			logger.Debug("Ignoring packet", slog.Int("type", int(hdr.Type())))
		}
	}()

	pkt.IncRef()

	return true
}

// ICMPv6ProtocolHandler forwards ICMPv6 sessions.
func (f *Forwarder) ICMPv6ProtocolHandler(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	go func() {
		defer pkt.DecRef()

		ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
		if len(ipHdr) < header.IPv6MinimumSize {
			f.logger.Debug("Dropping invalid IPv6 packet")
			return
		}

		// Fix up our rewritten protocol number.
		// See: rewrite_transport_protocol.go
		ipHdr[6] = uint8(icmp.ProtocolNumber6)

		hdr := header.ICMPv6(pkt.TransportHeader().Slice())
		if len(hdr) < header.ICMPv6MinimumSize {
			f.logger.Debug("Dropping invalid ICMPv6 packet")
			return
		}

		// checksums?

		logger := f.logger.With(
			slog.String("proto", "icmp6"),
			slog.String("src", id.RemoteAddress.String()),
			slog.String("dst", id.LocalAddress.String()))

		defer logger.Debug("Session finished")

		if hdr.Type() == header.ICMPv6EchoRequest {
			logger.Info("Forwarding echo request")

			ctx, cancel := context.WithTimeout(f.ctx, f.pingTimeout)
			defer cancel()

			dstAddr := util.AddrFrom(id.LocalAddress)

			// Unmap the destination address if NAT64 is enabled.
			dstAddr, isNAT64 := f.unmapNAT64Addr(dstAddr)

			network := "ip6"
			if isNAT64 {
				network = "ip4"
			}

			if err := f.dstNet.Ping(ctx, network, dstAddr.String()); err != nil {
				logger.Debug("Failed to ping destination", slog.Any("error", err))
				// TODO: if the destination is unreachable, send an ICMPv6 unreachable message.
				return
			}

			f.logger.Debug("Sending ICMPv6 echo reply")

			if err := f.sendICMPv6EchoReply(pkt); err != nil {
				logger.Warn("Failed to send echo reply", slog.Any("error", err))
			}
		} else {
			logger.Debug("Ignoring packet", slog.Int("type", int(hdr.Type())))
		}
	}()

	pkt.IncRef()

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

		logger.Info("Forwarding session")
		defer logger.Debug("Session finished")

		var wq waiter.Queue
		ep, tcpipErr := req.CreateEndpoint(&wq)
		if tcpipErr != nil {
			logger.Warn("Failed to create local endpoint",
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

		// Unmap the destination address if NAT64 is enabled.
		dstAddr, _ := f.unmapNAT64Addr(dstAddrPort.Addr())
		dstAddrPort = netip.AddrPortFrom(dstAddr, dstAddrPort.Port())

		// Connect to the destination.
		remote, err := f.dstNet.DialContext(ctx, "tcp", dstAddrPort.String())
		if err != nil {
			logger.Warn("Failed to dial destination", slog.Any("error", err))

			req.Complete(true)
			return
		}
		defer remote.Close()

		// Start forwarding.
		if _, err := contextio.SpliceContext(ctx, local, remote, nil); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("Failed to forward session", slog.Any("error", err))

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

	// Create endpoint as quickly as possible to avoid UDP race conditions, when
	// multiple frames are in flight.
	var wq waiter.Queue
	ep, tcpipErr := req.CreateEndpoint(&wq)
	if tcpipErr != nil {
		logger.Warn("Failed to create local endpoint",
			slog.String("error", tcpipErr.String()))

		return
	}

	go func() {
		logger.Info("Forwarding session")
		defer logger.Debug("Session finished")

		local := gonet.NewUDPConn(&wq, ep)
		defer local.Close()

		// Unmap the destination address if NAT64 is enabled.
		dstAddr, _ := f.unmapNAT64Addr(dstAddrPort.Addr())
		dstAddrPort = netip.AddrPortFrom(dstAddr, dstAddrPort.Port())

		remote, err := f.dstNet.DialContext(f.ctx, "udp", dstAddrPort.String())
		if err != nil {
			logger.Warn("Failed to dial destination", slog.Any("error", err))

			return
		}
		defer remote.Close()

		if _, err := contextio.SpliceContext(f.ctx, local, remote, &f.udpIdleTimeout); err != nil &&
			!(errors.Is(err, context.Canceled) || errors.Is(err, os.ErrDeadlineExceeded)) {
			logger.Warn("Failed to forward session", slog.Any("error", err))

			return
		}
	}()
}

func (f *Forwarder) sendICMPv4EchoReply(pkt *stack.PacketBuffer) error {
	replyData := stack.PayloadSince(pkt.TransportHeader())
	defer replyData.Release()

	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
	// source address MUST be one of its own IP addresses (but not a broadcast
	// or multicast address).
	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := f.srcStack.FindRoute(pkt.NICID, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return fmt.Errorf("failed to find route: %v", err)
	}
	defer r.Release()

	// Because IP and ICMP are so closely intertwined, we need to handcraft our
	// IP header to be able to follow RFC 792. The wording on page 13 is as
	// follows:
	//   IP Fields:
	//   Addresses
	//     The address of the source in an echo message will be the
	//     destination of the echo reply message.  To form an echo reply
	//     message, the source and destination addresses are simply reversed,
	//     the type code changed to 0, and the checksum recomputed.
	//
	// This was interpreted by early implementors to mean that all options must
	// be copied from the echo request IP header to the echo reply IP header
	// and this behaviour is still relied upon by some applications.
	//
	// Create a copy of the IP header we received, options and all, and change
	// The fields we need to alter.
	//
	// We need to produce the entire packet in the data segment in order to
	// use WriteHeaderIncludedPacket(). WriteHeaderIncludedPacket sets the
	// total length and the header checksum so we don't need to set those here.
	//
	// Take the base of the incoming request IP header but replace the options.
	ipOptions := ipHdr.Options()
	replyHeaderLength := uint8(header.IPv4MinimumSize + len(ipOptions))
	replyIPHdrView := buffer.NewView(int(replyHeaderLength))
	_, _ = replyIPHdrView.Write(ipHdr[:header.IPv4MinimumSize])
	_, _ = replyIPHdrView.Write(ipOptions)
	replyIPHdr := header.IPv4(replyIPHdrView.AsSlice())
	replyIPHdr.SetHeaderLength(replyHeaderLength)
	replyIPHdr.SetSourceAddress(r.LocalAddress())
	replyIPHdr.SetDestinationAddress(r.RemoteAddress())
	replyIPHdr.SetTTL(r.DefaultTTL())
	replyIPHdr.SetTotalLength(uint16(len(replyIPHdr) + len(replyData.AsSlice())))
	replyIPHdr.SetChecksum(0)
	replyIPHdr.SetChecksum(^replyIPHdr.CalculateChecksum())

	replyICMPHdr := header.ICMPv4(replyData.AsSlice())
	replyICMPHdr.SetType(header.ICMPv4EchoReply)
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyIPHdrView)
	_ = replyBuf.Append(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	if err := r.WriteHeaderIncludedPacket(replyPkt); err != nil {
		return fmt.Errorf("failed to write packet: %v", err)
	}

	return nil
}

func (f *Forwarder) sendICMPv6EchoReply(pkt *stack.PacketBuffer) error {
	icmpHdr := header.ICMPv6(pkt.TransportHeader().Slice())
	if len(icmpHdr) < header.ICMPv6MinimumSize {
		return errors.New("ICMPv6 packet too short")
	}

	ipHdr := header.IPv6(pkt.NetworkHeader().Slice())
	srcAddr := ipHdr.SourceAddress()
	dstAddr := ipHdr.DestinationAddress()

	// As per RFC 4291 section 2.7, multicast addresses must not be used as
	// source addresses in IPv6 packets.
	localAddr := dstAddr
	if header.IsV6MulticastAddress(dstAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := f.srcStack.FindRoute(pkt.NICID, localAddr, srcAddr, ipv6.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		return fmt.Errorf("failed to find route: %v", err)
	}
	defer r.Release()

	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
		Payload:            pkt.Data().ToBuffer(),
	})
	defer replyPkt.DecRef()

	replyICMPHdr := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
	replyPkt.TransportProtocolNumber = icmp.ProtocolNumber6
	copy(replyICMPHdr, icmpHdr)
	replyICMPHdr.SetType(header.ICMPv6EchoReply)
	replyData := replyPkt.Data()
	replyICMPHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      replyICMPHdr,
		Src:         r.LocalAddress(),
		Dst:         r.RemoteAddress(),
		PayloadCsum: replyData.Checksum(),
		PayloadLen:  replyData.Size(),
	}))
	replyTClass, _ := ipHdr.TOS()

	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      r.DefaultTTL(),
		// Even though RFC 4443 does not mention anything about it, Linux uses the
		// TrafficClass of the received echo request when replying.
		// https://github.com/torvalds/linux/blob/0280e3c58f9/net/ipv6/icmp.c#L797
		TOS: replyTClass,
	}, replyPkt); err != nil {
		return fmt.Errorf("failed to write packet: %v", err)
	}

	return nil
}

// Unmap the well-known NAT64 prefix (if present and NAT64 is enabled).
func (f *Forwarder) unmapNAT64Addr(addr netip.Addr) (netip.Addr, bool) {
	if f.enableNAT64 && addr.Is6() && f.nat64Prefix.Contains(addr) {
		addr = netip.AddrFrom4([4]byte(addr.AsSlice()[12:]))
		return addr, true
	}

	return addr, false
}
