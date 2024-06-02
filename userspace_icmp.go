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
	"bytes"
	"errors"
	"fmt"
	"math"
	stdnet "net"
	"net/netip"
	"os"
	"time"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/waiter"
)

type icmpPacketConn struct {
	network   string
	localAddr netip.Addr
	wq        waiter.Queue
	ep        tcpip.Endpoint
	deadline  *time.Timer
}

func (net *UserspaceNetwork) newICMPPacketConn(network string) (stdnet.PacketConn, error) {
	proto, _, err := parseNetwork(network)
	if err != nil {
		return nil, err
	}

	if proto != "ip" {
		return nil, ErrUnexpectedAddressType
	}

	pc := icmpPacketConn{
		network:  network,
		deadline: time.NewTimer(math.MaxInt64),
	}

	pc.localAddr, err = net.bindAddress(network, "")
	if err != nil {
		return nil, err
	}

	pn := header.IPv4ProtocolNumber
	tn := header.ICMPv4ProtocolNumber
	if pc.localAddr.Is6() {
		pn = header.IPv6ProtocolNumber
		tn = header.ICMPv6ProtocolNumber
	}

	var tcpipErr tcpip.Error
	pc.ep, tcpipErr = net.stack.NewEndpoint(tn, pn, &pc.wq)
	if tcpipErr != nil {
		return nil, fmt.Errorf("%v", tcpipErr)
	}

	return &pc, nil
}

func (pc *icmpPacketConn) Close() error {
	pc.deadline.Reset(0)
	pc.ep.Close()
	return nil
}

func (pc *icmpPacketConn) LocalAddr() stdnet.Addr {
	return &stdnet.IPAddr{IP: stdnet.IP(pc.localAddr.AsSlice())}
}

func (pc *icmpPacketConn) SetDeadline(t time.Time) error {
	// SetWriteDeadline is not implemented.
	return pc.SetReadDeadline(t)
}

func (pc *icmpPacketConn) SetReadDeadline(t time.Time) error {
	pc.deadline.Reset(time.Until(t))
	return nil
}

func (pc *icmpPacketConn) SetWriteDeadline(_ time.Time) error {
	return errors.New("not implemented")
}

func (pc *icmpPacketConn) ReadFrom(p []byte) (n int, addr stdnet.Addr, err error) {
	opErr := &stdnet.OpError{
		Op:     "read",
		Net:    pc.network,
		Source: &stdnet.IPAddr{IP: stdnet.IP(pc.localAddr.AsSlice())},
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	pc.wq.EventRegister(&waitEntry)
	defer pc.wq.EventUnregister(&waitEntry)

	select {
	case <-pc.deadline.C:
		opErr.Err = os.ErrDeadlineExceeded
		return 0, nil, opErr
	case <-notifyCh:
	}

	w := tcpip.SliceWriter(p)
	res, tcpipErr := pc.ep.Read(&w, tcpip.ReadOptions{
		NeedRemoteAddr: true,
	})
	if tcpipErr != nil {
		opErr.Err = fmt.Errorf("%s", tcpipErr)
		return 0, nil, opErr
	}

	return res.Count, &stdnet.IPAddr{IP: stdnet.IP(res.RemoteAddr.Addr.AsSlice())}, nil
}

func (pc *icmpPacketConn) WriteTo(p []byte, addr stdnet.Addr) (int, error) {
	opErr := &stdnet.OpError{
		Op:     "write",
		Net:    pc.network,
		Source: &stdnet.IPAddr{IP: stdnet.IP(pc.localAddr.AsSlice())},
	}

	host, _, err := stdnet.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}

	na, err := netip.ParseAddr(host)
	if err != nil {
		opErr.Err = err
		return 0, opErr
	}

	if !((na.Is4() && pc.localAddr.Is4()) || (na.Is6() && pc.localAddr.Is6())) {
		opErr.Err = errors.New("mismatched protocols")
		return 0, opErr
	}

	buf := bytes.NewReader(p)
	fa, _ := convertToFullAddr(nicID, netip.AddrPortFrom(na, 0))
	// won't block, no deadlines
	n, tcpipErr := pc.ep.Write(buf, tcpip.WriteOptions{
		To: &fa,
	})
	if tcpipErr != nil {
		opErr.Err = fmt.Errorf("%s", tcpipErr)
		return int(n), opErr
	}

	return int(n), nil
}
