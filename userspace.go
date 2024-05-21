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
	"net/netip"
	"os"
	"strconv"
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
	"github.com/noisysockets/resolver"
	"golang.org/x/sync/errgroup"
)

const (
	nicID                            = 1
	outboundQueueSize                = 256
	maxInFlightTCPConnectionAttempts = 16
)

var (
	// Ensure that UserspaceNetwork implements Network interface.
	_ Network = (*UserspaceNetwork)(nil)
)

type UserspaceNetworkConfig struct {
	// Hostname is the hostname of the local process.
	Hostname string
	// Addresses is a list of IP addresses/IP prefixes to add.
	Addresses []netip.Prefix
	// ResolverFactory is an optional factory to create a DNS resolver.
	ResolverFactory ResolverFactory
	// EnableSpoofing allows outgoing packets to have a source address different
	// from the address assigned to the NIC.
	EnableSpoofing bool
	// EnablePromiscuousMode allows incoming packets to have a destination address
	// different from the address assigned to the NIC.
	EnablePromiscuousMode bool
	// DisableIPv4 disables IPv4 support.
	DisableIPv4 bool
	// DisableIPv6 disables IPv6 support.
	DisableIPv6 bool
	// TCPProtocolHandler is a callback that is invoked when a TCP packet is received.
	TCPProtocolHandler func(*tcp.ForwarderRequest)
	// UDPProtocolHandler is a callback that is invoked when a UDP packet is received.
	UDPProtocolHandler func(*udp.ForwarderRequest)
	// PacketCaptureWriter is an optional writer to write a packet capture file to.
	// If nil, no packet capture file will be written.
	// This is useful for debugging network issues.
	PacketCaptureWriter io.Writer
}

type UserspaceNetwork struct {
	logger       *slog.Logger
	nic          Interface
	hostname     string
	resolver     resolver.Resolver
	stack        *stack.Stack
	ep           *channel.Endpoint
	notifyHandle *channel.NotificationHandle
	outbound     chan *stack.PacketBuffer
	tasks        *errgroup.Group
	tasksCtx     context.Context
	tasksCancel  context.CancelFunc
}

// Userspace returns a userspace Network implementation based on Netstack from
// the gVisor project.
func Userspace(ctx context.Context, logger *slog.Logger, nic Interface, conf *UserspaceNetworkConfig) (*UserspaceNetwork, error) {
	if conf == nil {
		conf = &UserspaceNetworkConfig{}
	}

	stackOpts := stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	}

	if !conf.DisableIPv4 {
		stackOpts.NetworkProtocols = append(stackOpts.NetworkProtocols, ipv4.NewProtocol)
	}
	if !conf.DisableIPv6 {
		stackOpts.NetworkProtocols = append(stackOpts.NetworkProtocols, ipv6.NewProtocol)
	}

	tasksCtx, tasksCancel := context.WithCancel(ctx)
	tasks, tasksCtx := errgroup.WithContext(tasksCtx)

	net := &UserspaceNetwork{
		logger:      logger,
		nic:         nic,
		hostname:    conf.Hostname,
		resolver:    resolver.IP(),
		stack:       stack.New(stackOpts),
		ep:          channel.New(outboundQueueSize, uint32(nic.MTU()), ""),
		outbound:    make(chan *stack.PacketBuffer),
		tasks:       tasks,
		tasksCtx:    tasksCtx,
		tasksCancel: tasksCancel,
	}

	net.notifyHandle = net.ep.AddNotify(net)

	if conf.ResolverFactory != nil {
		net.resolver = conf.ResolverFactory(net.DialContext)
	}

	var ep stack.LinkEndpoint = net.ep
	if conf.PacketCaptureWriter != nil {
		if snifferEP, err := sniffer.NewWithWriter(ep, conf.PacketCaptureWriter, uint32(nic.MTU())); err != nil {
			_ = net.Close()
			return nil, fmt.Errorf("failed to create pcap sniffer: %v", err)
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

		// Ignore the address if the protocol is disabled.
		if conf.DisableIPv4 && pn == ipv4.ProtocolNumber {
			continue
		}
		if conf.DisableIPv6 && pn == ipv6.ProtocolNumber {
			continue
		}

		protocolAddress := tcpip.ProtocolAddress{
			Protocol: pn,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(addr.Addr().Unmap().AsSlice()),
				PrefixLen: addr.Bits(),
			},
		}

		if err := net.stack.AddProtocolAddress(nicID, protocolAddress, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("could not add address: %v", err)
		}
	}

	// Route all outbound packets to the NIC.
	if !conf.DisableIPv4 {
		net.stack.AddRoute(tcpip.Route{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		})
	}
	if !conf.DisableIPv6 {
		net.stack.AddRoute(tcpip.Route{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		})
	}

	// Allow outgoing packets to have a source address different from the address
	// assigned to the NIC.
	if err := net.stack.SetSpoofing(nicID, conf.EnableSpoofing); err != nil {
		return nil, fmt.Errorf("failed to configure spoofing: %v", err)
	}

	// Allows outgoing packets to have a destination address different from the
	// address assigned to the NIC.
	if err := net.stack.SetPromiscuousMode(nicID, conf.EnablePromiscuousMode); err != nil {
		return nil, fmt.Errorf("failed to configure promiscuous mode: %v", err)
	}

	// Register custom protocol handlers (if any).
	if conf.TCPProtocolHandler != nil {
		tcpFwd := tcp.NewForwarder(net.stack, 0, maxInFlightTCPConnectionAttempts, conf.TCPProtocolHandler)
		net.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	}

	if conf.UDPProtocolHandler != nil {
		udpFwd := udp.NewForwarder(net.stack, conf.UDPProtocolHandler)
		net.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	}

	// Begin copying packets to/from the NIC.
	net.tasks.Go(net.copyInboundFromNIC)
	net.tasks.Go(net.copyOutboundToNIC)

	return net, nil
}

func (net *UserspaceNetwork) Close() error {
	net.ep.RemoveNotify(net.notifyHandle)
	net.ep.Close()

	if net.stack.HasNIC(nicID) {
		if err := net.stack.RemoveNIC(nicID); err != nil {
			return fmt.Errorf("failed to remove NIC: %v", err)
		}
	}

	// Stop copying packets to/from the NIC.
	net.tasksCancel()
	if err := net.tasks.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	net.stack.Close()

	return nil
}

func (net *UserspaceNetwork) WriteNotify() {
	pkt := net.ep.Read()
	if pkt == nil {
		return
	}

	net.outbound <- pkt
}

func (net *UserspaceNetwork) copyInboundFromNIC() error {
	defer func() {
		net.logger.Debug("Finished copying inbound packets")

		close(net.outbound)
		net.tasksCancel()
	}()

	batchSize := net.nic.BatchSize()
	mtu := net.nic.MTU()

	sizes := make([]int, batchSize)
	bufs := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, mtu)
	}

	net.logger.Debug("Started copying inbound packets")

	for {
		n, err := net.nic.Read(net.tasksCtx, bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, stdnet.ErrClosed) ||
				errors.Is(err, os.ErrClosed) {
				return nil
			}

			return err
		}

		for i := 0; i < n; i++ {
			buf := bufs[i][:sizes[i]]

			var protocolNumber tcpip.NetworkProtocolNumber
			switch header.IPVersion(buf) {
			case header.IPv4Version:
				protocolNumber = header.IPv4ProtocolNumber
			case header.IPv6Version:
				protocolNumber = header.IPv6ProtocolNumber
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
			net.ep.InjectInbound(protocolNumber, pkt)
		}
	}
}

func (net *UserspaceNetwork) copyOutboundToNIC() error {
	defer func() {
		net.logger.Debug("Finished copying outbound packets")
	}()

	batchSize := net.nic.BatchSize()
	mtu := net.nic.MTU()

	sizes := make([]int, batchSize)
	bufs := make([][]byte, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, mtu)
	}

	processPacket := func(idx int, pkt *stack.PacketBuffer) {
		defer pkt.DecRef()

		view := pkt.ToView()
		sizes[idx], _ = view.Read(bufs[idx])
		view.Release()
	}

	writeBatch := func(n int) error {
		for i := 0; i < n; {
			writtenPackets, err := net.nic.Write(net.tasksCtx, bufs[i:n], sizes[i:n], 0)
			if err != nil {
				return fmt.Errorf("failed to write packets: %v", err)
			}

			i += writtenPackets
		}

		return nil
	}

	net.logger.Debug("Started copying outbound packets")

	for {
		select {
		case <-net.tasksCtx.Done():
			return nil
		// Wait for atleast one packet to be available.
		case pkt, ok := <-net.outbound:
			if !ok {
				return stdnet.ErrClosed
			}

			processPacket(0, pkt)
			n := 1

			// Then read as many packets as possible (without blocking).
			for ; n < batchSize; n++ {
				select {
				case <-net.tasksCtx.Done():
					// Any remaining undelivered packets will be dropped.
					return nil
				case pkt, ok := <-net.outbound:
					if !ok {
						if err := writeBatch(n); err != nil {
							return err
						}

						return stdnet.ErrClosed
					}

					processPacket(n, pkt)
				default:
					// No more packets to read
					goto WRITE_BATCH
				}
			}

		WRITE_BATCH:
			if err := writeBatch(n); err != nil {
				return err
			}
		}
	}
}

func (net *UserspaceNetwork) Hostname() (string, error) {
	if net.hostname != "" {
		return net.hostname, nil
	}
	return "", errors.New("hostname not set")
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
	return net.resolver.LookupHost(ctx, host)
}

func (net *UserspaceNetwork) Dial(network, address string) (stdnet.Conn, error) {
	return net.DialContext(context.Background(), network, address)
}

func (net *UserspaceNetwork) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	opErr := &stdnet.OpError{Op: "dial", Net: network}

	proto, useIPV4, useIPV6, err := parseNetwork(network)
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

	allAddrs, err := net.resolver.LookupHost(ctx, host)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	addrs := parseAndFilterAddrs(allAddrs, useIPV4, useIPV6)
	if len(addrs) == 0 {
		opErr.Err = ErrNoSuitableAddress
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

	proto, useIPV4, useIPV6, err := parseNetwork(network)
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

	addr, err := net.bindAddress(host, useIPV4, useIPV6)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	fa, pn := convertToFullAddr(nicID, netip.AddrPortFrom(addr, uint16(port)))

	return gonet.ListenTCP(net.stack, fa, pn)
}

func (net *UserspaceNetwork) ListenPacket(network, address string) (stdnet.PacketConn, error) {
	opErr := &stdnet.OpError{Op: "listen", Net: network}

	proto, useIPV4, useIPV6, err := parseNetwork(network)
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

	addr, err := net.bindAddress(host, useIPV4, useIPV6)
	if err != nil {
		opErr.Err = err
		return nil, opErr
	}

	fa, pn := convertToFullAddr(nicID, netip.AddrPortFrom(addr, uint16(port)))

	return gonet.DialUDP(net.stack, &fa, nil, pn)
}

// TODO: binding to both IPv4 and IPv6 / multiple addresses.
func (net *UserspaceNetwork) bindAddress(host string, useIPV4, useIPV6 bool) (addr netip.Addr, err error) {
	allNICAddrs := net.stack.AllAddresses()[nicID]

	if host != "" {
		allAddrs, err := net.resolver.LookupHost(context.Background(), host)
		if err != nil {
			return addr, err
		}

		addrs := parseAndFilterAddrs(allAddrs, useIPV4, useIPV6)
		if len(addrs) == 0 {
			return addr, ErrNoSuitableAddress
		}

		// See if we find a matching address assigned to the NIC.
		for _, addr := range addrs {
			for _, nicAddr := range allNICAddrs {
				if nicAddr.AddressWithPrefix.Address == tcpip.AddrFromSlice(addr.Unmap().AsSlice()) {
					return addr, nil
				}
			}
		}

		// If it's not a wildcard address, return an error.
		if !addrs[0].IsUnspecified() {
			return addr, ErrNoSuitableAddress
		}
	}

	var pn tcpip.NetworkProtocolNumber
	if useIPV4 {
		pn = ipv4.ProtocolNumber
	} else {
		pn = ipv6.ProtocolNumber
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

func convertToFullAddr(nicID tcpip.NICID, addrPort netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var pn tcpip.NetworkProtocolNumber
	if addrPort.Addr().Unmap().Is4() {
		pn = ipv4.ProtocolNumber
	} else {
		pn = ipv6.ProtocolNumber
	}

	return tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addrPort.Addr().Unmap().AsSlice()),
		Port: addrPort.Port(),
	}, pn
}
