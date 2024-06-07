// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-go,
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	stdnet "net"

	"github.com/noisysockets/netstack/pkg/buffer"
	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/adapters/gonet"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/link/channel"
	"github.com/noisysockets/netstack/pkg/tcpip/link/sniffer"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv4"
	"github.com/noisysockets/netstack/pkg/tcpip/network/ipv6"
	"github.com/noisysockets/netstack/pkg/tcpip/stack"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/icmp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/udp"
	"github.com/noisysockets/netutil/triemap"
	"github.com/noisysockets/network/internal/iptables/matcher"
	"github.com/noisysockets/network/internal/iptables/target"
	"github.com/noisysockets/network/internal/protocol"
	"github.com/noisysockets/network/internal/util"
	"github.com/noisysockets/pinger"
	"github.com/noisysockets/resolver"
	"golang.org/x/sync/errgroup"
)

const (
	nicID             = 1
	outboundQueueSize = 256
)

// Ensure that UserspaceNetwork implements Network interface.
var _ Network = (*UserspaceNetwork)(nil)

type UserspaceNetworkConfig struct {
	// Hostname is the hostname of the local process.
	Hostname string
	// Domain is the local domain of the network.
	Domain string
	// Addresses is a list of IP addresses/IP prefixes to add.
	Addresses []netip.Prefix
	// ResolverFactory is an optional factory to create a DNS resolver.
	ResolverFactory ResolverFactory
	// PacketCaptureWriter is an optional writer to write a packet capture file to.
	// If nil, no packet capture file will be written.
	// This is useful for debugging network issues.
	PacketCaptureWriter io.Writer
	// PacketPool is the pool from which packets are borrowed.
	// If not specified, an unbounded pool will be created.
	PacketPool *PacketPool
}

type UserspaceNetwork struct {
	logger        *slog.Logger
	nic           Interface
	hostname      string
	domain        string
	localPrefixes *triemap.TrieMap[struct{}]
	resolver      resolver.Resolver
	stack         *stack.Stack
	ep            *channel.Endpoint
	notifyHandle  *channel.NotificationHandle
	outbound      chan *stack.PacketBuffer
	tasks         *errgroup.Group
	tasksCtx      context.Context
	tasksCancel   context.CancelFunc
	closeOnce     sync.Once
	pinger        *pinger.Pinger
	packetPool    *PacketPool
}

// Userspace returns a userspace Network implementation based on Netstack from
// the gVisor project.
func Userspace(ctx context.Context, logger *slog.Logger, nic Interface, conf UserspaceNetworkConfig) (*UserspaceNetwork, error) {
	localPrefixes := triemap.New[struct{}]()
	for _, addr := range conf.Addresses {
		localPrefixes.Insert(addr, struct{}{})
	}

	packetPool := conf.PacketPool
	if packetPool == nil {
		packetPool = NewPacketPool(0, false)
	}

	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
			// A hack to allow intercepting and forwarding ICMP packets.
			protocol.NewProtocolForwardedICMPv4,
			protocol.NewProtocolForwardedICMPv6,
		},
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		DefaultIPTables: func(clock tcpip.Clock, rand *rand.Rand) *stack.IPTables {
			return defaultIPTables(clock, rand, localPrefixes)
		},
	}

	tasksCtx, tasksCancel := context.WithCancel(ctx)
	tasks, tasksCtx := errgroup.WithContext(tasksCtx)

	net := &UserspaceNetwork{
		logger:        logger,
		nic:           nic,
		hostname:      conf.Hostname,
		domain:        conf.Domain,
		localPrefixes: localPrefixes,
		resolver:      resolver.Literal(),
		stack:         stack.New(stackOpts),
		ep:            channel.New(outboundQueueSize, uint32(nic.MTU()), ""),
		outbound:      make(chan *stack.PacketBuffer),
		tasks:         tasks,
		tasksCtx:      tasksCtx,
		tasksCancel:   tasksCancel,
		packetPool:    packetPool,
	}

	net.notifyHandle = net.ep.AddNotify(net)

	if conf.ResolverFactory != nil {
		var err error
		net.resolver, err = conf.ResolverFactory(net.DialContext)
		if err != nil {
			_ = net.Close()
			return nil, fmt.Errorf("failed to create resolver: %w", err)
		}
	}

	net.pinger = pinger.New(
		pinger.WithLogger(logger),
		pinger.WithResolver(net.resolver),
		pinger.WithPacketConnFactory(net.newICMPPacketConn),
	)

	var ep stack.LinkEndpoint = net.ep
	if conf.PacketCaptureWriter != nil {
		if snifferEP, err := sniffer.NewWithWriter(ep, conf.PacketCaptureWriter, uint32(nic.MTU())); err != nil {
			_ = net.Close()
			return nil, fmt.Errorf("failed to create pcap sniffer: %w", err)
		} else {
			ep = snifferEP
		}
	}

	// Create a primary NIC.
	if err := net.stack.CreateNIC(nicID, ep); err != nil {
		_ = net.Close()
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	// Assign addresses to the NIC.
	for _, addr := range conf.Addresses {
		var pn tcpip.NetworkProtocolNumber
		if addr.Addr().Unmap().Is4() {
			pn = ipv4.ProtocolNumber
		} else if addr.Addr().Is6() {
			pn = ipv6.ProtocolNumber
		}

		protocolAddress := tcpip.ProtocolAddress{
			Protocol: pn,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   util.TcpipAddrFrom(addr.Addr()),
				PrefixLen: addr.Bits(),
			},
		}

		if err := net.stack.AddProtocolAddress(nicID, protocolAddress, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("could not add address: %v", err)
		}
	}

	// Route all outbound packets to the NIC.
	net.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	// Begin copying packets to/from the NIC.
	net.tasks.Go(net.copyInboundFromNIC)
	net.tasks.Go(net.copyOutboundToNIC)

	return net, nil
}

func (net *UserspaceNetwork) WriteNotify() {
	pkt := net.ep.Read()
	if pkt == nil {
		return
	}

	net.outbound <- pkt
}

func (net *UserspaceNetwork) Close() error {
	var err error
	net.closeOnce.Do(func() {
		net.ep.RemoveNotify(net.notifyHandle)
		net.ep.Close()

		if net.stack.HasNIC(nicID) {
			if tcpipErr := net.stack.RemoveNIC(nicID); tcpipErr != nil {
				err = fmt.Errorf("failed to remove NIC: %v", err)
				return
			}
		}

		// Stop copying packets to/from the NIC.
		net.tasksCancel()

		if tasksErr := net.tasks.Wait(); tasksErr != nil && !errors.Is(tasksErr, context.Canceled) {
			err = tasksErr
			return
		}

		net.stack.Close()
	})

	return err
}

// Stack returns the underlying netstack stack.
func (net *UserspaceNetwork) Stack() *stack.Stack {
	return net.stack
}

// EnableForwarding enables forwarding of network sessions using the provided
// Forwarder implementation.
func (net *UserspaceNetwork) EnableForwarding(fwd Forwarder) error {
	// Allow outgoing packets to have a source address different from the address
	// assigned to the NIC.
	if err := net.stack.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("failed to enable spoofing: %v", err)
	}

	// Allows incoming packets to have a destination address different from the
	// address assigned to the NIC.
	if err := net.stack.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("failed to enable promiscuous mode: %v", err)
	}

	type packetHandler func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool

	// TODO: extract this out into a kind of packet handler muxer.
	handlerForDestination := func(h packetHandler) packetHandler {
		return func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
			dstAddr := util.AddrFrom(id.LocalAddress)

			if _, ok := net.localPrefixes.Get(dstAddr); ok {
				// Not handled by the forwarder (local traffic).
				return false
			}

			if !fwd.ValidDestination(dstAddr) {
				// Not handled by the forwarder.
				return false
			}

			return h(id, pkt)
		}
	}

	net.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, handlerForDestination(fwd.TCPProtocolHandler))
	net.stack.SetTransportProtocolHandler(udp.ProtocolNumber, handlerForDestination(fwd.UDPProtocolHandler))
	net.stack.SetTransportProtocolHandler(protocol.ForwardedICMPv4ProtocolNumber, handlerForDestination(fwd.ICMPv4ProtocolHandler))
	net.stack.SetTransportProtocolHandler(protocol.ForwardedICMPv6ProtocolNumber, handlerForDestination(fwd.ICMPv6ProtocolHandler))

	return nil
}

func (net *UserspaceNetwork) copyInboundFromNIC() error {
	defer func() {
		net.logger.Debug("Finished copying inbound packets")

		close(net.outbound)
		net.tasksCancel()
	}()

	batchSize := net.nic.BatchSize()
	mtu := net.nic.MTU()

	packets := make([]*Packet, batchSize)
	for i := 0; i < batchSize; i++ {
		packets[i] = net.packetPool.Borrow()
	}
	defer func() {
		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}()

	net.logger.Debug("Started copying inbound packets")

	for {
		n, err := net.nic.Read(net.tasksCtx, packets, 0)
		if err != nil {
			if errors.Is(err, stdnet.ErrClosed) ||
				errors.Is(err, os.ErrClosed) {
				return nil
			}

			return err
		}

		for i := 0; i < n; i++ {
			pkt := packets[i]

			if pkt.Size > mtu {
				net.logger.Warn("Inbound packet size exceeds MTU",
					slog.Int("size", pkt.Size),
					slog.Int("mtu", mtu))
			}

			buf := pkt.Bytes()

			var protocolNumber tcpip.NetworkProtocolNumber
			switch header.IPVersion(buf) {
			case header.IPv4Version:
				protocolNumber = header.IPv4ProtocolNumber
			case header.IPv6Version:
				protocolNumber = header.IPv6ProtocolNumber
			}

			net.ep.InjectInbound(protocolNumber,
				stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)}))
		}
	}
}

func (net *UserspaceNetwork) copyOutboundToNIC() error {
	defer func() {
		net.logger.Debug("Finished copying outbound packets")
	}()

	batchSize := net.nic.BatchSize()
	packets := make([]*Packet, 0, batchSize)

	processPacket := func(stackPkt *stack.PacketBuffer) {
		defer stackPkt.DecRef()

		pkt := net.packetPool.Borrow()
		view := stackPkt.ToView()
		pkt.Size, _ = view.Read(pkt.Buf[:])
		view.Release()

		packets = append(packets, pkt)
	}

	net.logger.Debug("Started copying outbound packets")

	for {
		select {
		case <-net.tasksCtx.Done():
			return nil
		// Wait for atleast one packet to be available.
		case stackPkt, ok := <-net.outbound:
			if !ok {
				return stdnet.ErrClosed
			}

			processPacket(stackPkt)

			// Then read as many packets as possible (without blocking).
			for i := 1; i < batchSize; i++ {
				select {
				case <-net.tasksCtx.Done():
					// Any remaining undelivered packets will be dropped.
					for i, pkt := range packets {
						pkt.Release()
						packets[i] = nil
					}

					return nil
				case stackPkt, ok := <-net.outbound:
					if !ok {
						_, err := net.nic.Write(net.tasksCtx, packets)
						if err != nil {
							return fmt.Errorf("failed to write packets: %w", err)
						}

						return stdnet.ErrClosed
					}

					processPacket(stackPkt)
				default:
					// No more packets to read
					goto WRITE_BATCH
				}
			}

		WRITE_BATCH:
			_, err := net.nic.Write(net.tasksCtx, packets)
			if err != nil {
				return fmt.Errorf("failed to write packets: %w", err)
			}

			packets = packets[:0]
		}
	}
}

func (net *UserspaceNetwork) Hostname() (string, error) {
	if net.hostname != "" {
		return net.hostname, nil
	}
	return "", errors.New("hostname not set")
}

func (net *UserspaceNetwork) Domain() (string, error) {
	if net.domain != "" {
		return net.domain, nil
	}
	return "", errors.New("domain not set")
}

func (net *UserspaceNetwork) InterfaceAddrs() (addrs []stdnet.Addr, err error) {
	for _, addr := range net.stack.AllAddresses()[nicID] {
		ip := stdnet.IP(addr.AddressWithPrefix.Address.AsSlice())

		switch addr.Protocol {
		case ipv4.ProtocolNumber:
			if addr.AddressWithPrefix.PrefixLen == 32 {
				addrs = append(addrs, &stdnet.IPAddr{IP: ip})
			} else {
				addrs = append(addrs, &stdnet.IPNet{
					IP:   ip,
					Mask: stdnet.CIDRMask(int(addr.AddressWithPrefix.PrefixLen), 32),
				})
			}
		case ipv6.ProtocolNumber:
			if addr.AddressWithPrefix.PrefixLen == 128 {
				addrs = append(addrs, &stdnet.IPAddr{IP: ip})
			} else {
				addrs = append(addrs, &stdnet.IPNet{
					IP:   ip,
					Mask: stdnet.CIDRMask(int(addr.AddressWithPrefix.PrefixLen), 128),
				})
			}
		default:
			return nil, fmt.Errorf("unknown protocol number: %v", addr.Protocol)
		}
	}

	return addrs, nil
}

func (net *UserspaceNetwork) LookupHost(host string) ([]string, error) {
	return net.LookupHostContext(context.Background(), host)
}

func (net *UserspaceNetwork) LookupHostContext(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	return util.Strings(addrs), nil
}

func (net *UserspaceNetwork) Dial(network, address string) (stdnet.Conn, error) {
	return net.DialContext(context.Background(), network, address)
}

func (net *UserspaceNetwork) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	opErr := &stdnet.OpError{Op: "dial", Net: network}

	proto, ipVersion, err := parseNetwork(network)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		opErr.Err = &stdnet.AddrError{Err: err.Error(), Addr: address}
		return nil, opErr
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		opErr.Err = ErrInvalidPort
		return nil, opErr
	}

	addrs, err := net.resolver.LookupNetIP(ctx, "ip"+ipVersion, host)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	// The error from the first address is most relevant.
	var firstErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			opErr.Err = ctx.Err()
			if errors.Is(opErr.Err, context.DeadlineExceeded) {
				opErr.Err = os.ErrDeadlineExceeded
			}
			return nil, opErr
		default:
		}

		dialCtx := ctx
		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			partialDeadline, err := partialDeadline(time.Now(), deadline, len(addrs)-i)
			if err != nil {
				// Ran out of time.
				if firstErr == nil {
					firstErr = &stdnet.OpError{Op: "dial", Net: network, Err: err}
				}
				break
			}
			if partialDeadline.Before(deadline) {
				var cancel context.CancelFunc
				dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
				defer cancel()
			}
		}

		fa, pn := convertToFullAddr(nicID, netip.AddrPortFrom(addr, uint16(port)))

		var c stdnet.Conn
		switch proto {
		case "tcp":
			c, err = gonet.DialContextTCP(dialCtx, net.stack, fa, pn)
		case "udp":
			c, err = gonet.DialUDP(net.stack, nil, &fa, pn)
		default:
			err = &stdnet.OpError{Op: "dial", Net: network, Err: ErrUnexpectedAddressType}
		}
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		opErr.Err = ErrMissingAddress
		return nil, opErr
	}

	return nil, firstErr
}

func (net *UserspaceNetwork) Listen(network, address string) (stdnet.Listener, error) {
	opErr := &stdnet.OpError{Op: "listen", Net: network}

	proto, ipVersion, err := parseNetwork(network)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	if proto != "tcp" {
		opErr.Err = ErrUnexpectedAddressType
		return nil, opErr
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		opErr.Err = &stdnet.AddrError{Err: err.Error(), Addr: address}
		return nil, opErr
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		opErr.Err = ErrInvalidPort
		return nil, opErr
	}

	addr, err := net.bindAddress("ip"+ipVersion, host)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	fa, pn := convertToFullAddr(nicID, netip.AddrPortFrom(addr, uint16(port)))

	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *UserspaceNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	opErr := &stdnet.OpError{Op: "listen", Net: network}

	proto, ipVersion, err := parseNetwork(network)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	if proto != "udp" {
		opErr.Err = ErrUnexpectedAddressType
		return nil, opErr
	}

	host, sport, err := stdnet.SplitHostPort(address)
	if err != nil {
		opErr.Err = &stdnet.AddrError{Err: err.Error(), Addr: address}
		return nil, opErr
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		opErr.Err = ErrInvalidPort
		return nil, opErr
	}

	addr, err := net.bindAddress("ip"+ipVersion, host)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	fa, pn := convertToFullAddr(nicID, netip.AddrPortFrom(addr, uint16(port)))

	return gonet.DialUDP(net.stack, &fa, nil, pn)
}

func (net *UserspaceNetwork) Ping(ctx context.Context, network, host string) error {
	return net.pinger.Ping(ctx, network, host)
}

// TODO: binding to both IPv4 and IPv6 / multiple addresses?
func (net *UserspaceNetwork) bindAddress(network, host string) (addr netip.Addr, err error) {
	allNICAddrs := net.stack.AllAddresses()[nicID]

	if host != "" {
		addrs, err := net.resolver.LookupNetIP(context.Background(), network, host)
		if err != nil {
			return addr, err
		}

		// See if we find a matching address assigned to the NIC.
		for _, addr := range addrs {
			for _, nicAddr := range allNICAddrs {
				if nicAddr.AddressWithPrefix.Address == util.TcpipAddrFrom(addr) {
					return addr, nil
				}
			}
		}

		// If it's not a wildcard address, return an error.
		if !addrs[0].IsUnspecified() {
			return addr, ErrNoSuitableAddress
		}
	}

	var hasV4, hasV6 bool
	for _, nicAddr := range allNICAddrs {
		addr, ok := netip.AddrFromSlice(nicAddr.AddressWithPrefix.Address.AsSlice())
		if !ok {
			continue
		}

		// Make sure not a broadcast/multicast address.
		if (addr.Unmap().Is4() && addr.Unmap() == netip.AddrFrom4([4]byte{255, 255, 255, 255})) || addr.IsMulticast() {
			continue
		}

		if addr.Unmap().Is4() {
			hasV4 = true
		} else if addr.Is6() {
			hasV6 = true
		}
	}

	if (network == "ip4" && !hasV4) || (network == "ip6" && !hasV6) {
		return addr, ErrNoSuitableAddress
	}

	var pn tcpip.NetworkProtocolNumber
	if hasV6 && network != "ip4" {
		pn = ipv6.ProtocolNumber
	} else {
		pn = ipv4.ProtocolNumber
	}

	mainAddress, tcpipErr := net.stack.GetMainNICAddress(nicID, pn)
	if tcpipErr != nil {
		return addr, ErrNoSuitableAddress
	}

	var ok bool
	addr, ok = netip.AddrFromSlice(mainAddress.Address.AsSlice())
	if !ok {
		return addr, ErrNoSuitableAddress
	}

	return addr, nil
}

// By default it is not possible to intercept and forward ICMP packets within netstack.
// This is due to ICMP dispatching occuring at lower layer in the network stack.
// We use iptables to implement a workaround which involves rewriting the ICMP protocol
// number and passing it to the stack (where we subsequently catch and forward it).
func defaultIPTables(clock tcpip.Clock, rand *rand.Rand, localPrefixes *triemap.TrieMap[struct{}]) *stack.IPTables {
	const (
		RewriteICMPRule = iota
		AllowRule
	)

	nonLocal := matcher.Not(matcher.Destination(localPrefixes))

	ipV4FilterTable := stack.Table{
		Rules: []stack.Rule{
			// RewriteICMPRule
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      header.ICMPv4ProtocolNumber,
					CheckProtocol: true,
				},
				Matchers: []stack.Matcher{nonLocal},
				Target:   target.RewriteTransportProtocol(protocol.ForwardedICMPv4ProtocolNumber),
			},
			// AllowRule
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  AllowRule,
			stack.Input:       RewriteICMPRule,
			stack.Forward:     AllowRule,
			stack.Output:      AllowRule,
			stack.Postrouting: AllowRule,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  stack.HookUnset,
			stack.Input:       stack.HookUnset,
			stack.Forward:     stack.HookUnset,
			stack.Output:      stack.HookUnset,
			stack.Postrouting: stack.HookUnset,
		},
	}

	ipV6FilterTable := stack.Table{
		Rules: []stack.Rule{
			// RewriteICMPRule
			{
				Filter: stack.IPHeaderFilter{
					Protocol:      header.ICMPv6ProtocolNumber,
					CheckProtocol: true,
				},
				Matchers: []stack.Matcher{nonLocal},
				Target:   target.RewriteTransportProtocol(protocol.ForwardedICMPv6ProtocolNumber),
			},
			// AllowRule
			{Target: &stack.AcceptTarget{NetworkProtocol: header.IPv6ProtocolNumber}},
		},
		BuiltinChains: [stack.NumHooks]int{
			stack.Prerouting:  AllowRule,
			stack.Input:       RewriteICMPRule,
			stack.Forward:     AllowRule,
			stack.Output:      AllowRule,
			stack.Postrouting: AllowRule,
		},
		Underflows: [stack.NumHooks]int{
			stack.Prerouting:  stack.HookUnset,
			stack.Input:       stack.HookUnset,
			stack.Forward:     stack.HookUnset,
			stack.Output:      stack.HookUnset,
			stack.Postrouting: stack.HookUnset,
		},
	}

	tables := stack.DefaultTables(clock, rand)
	tables.ReplaceTable(stack.FilterID, ipV4FilterTable, false)
	tables.ReplaceTable(stack.FilterID, ipV6FilterTable, true)

	return tables
}

func convertToFullAddr(nicID tcpip.NICID, addrPort netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var pn tcpip.NetworkProtocolNumber
	if addrPort.Addr().Unmap().Is4() {
		pn = ipv4.ProtocolNumber
	} else {
		pn = ipv6.ProtocolNumber
	}

	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: util.TcpipAddrFrom(addrPort.Addr()),
		Port: addrPort.Port(),
	}, pn
}
