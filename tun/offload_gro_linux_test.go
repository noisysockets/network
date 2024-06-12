//go:build linux

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

package tun

import (
	"net/netip"
	"testing"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	offset = VirtioNetHdrLen
)

var (
	ip4PortA   = netip.MustParseAddrPort("192.0.2.1:1")
	ip4PortB   = netip.MustParseAddrPort("192.0.2.2:1")
	ip4PortC   = netip.MustParseAddrPort("192.0.2.3:1")
	ip6PortA   = netip.MustParseAddrPort("[2001:db8::1]:1")
	ip6PortB   = netip.MustParseAddrPort("[2001:db8::2]:1")
	ip6PortC   = netip.MustParseAddrPort("[2001:db8::3]:1")
	packetPool = network.NewPacketPool(0, false)
)

func udp4PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, payloadLen int, ipFn func(*header.IPv4Fields)) *network.Packet {
	pkt := packetPool.Borrow()
	pkt.Offset = offset
	pkt.Size = 28 + int(payloadLen)
	b := pkt.Buf[:]

	ipv4H := header.IPv4(b[offset:])
	srcAs4 := srcIPPort.Addr().As4()
	dstAs4 := dstIPPort.Addr().As4()
	ipFields := &header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(srcAs4[:]),
		DstAddr:     tcpip.AddrFromSlice(dstAs4[:]),
		Protocol:    unix.IPPROTO_UDP,
		TTL:         64,
		TotalLength: uint16(28 + payloadLen),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv4H.Encode(ipFields)
	udpH := header.UDP(b[offset+20:])
	udpH.Encode(&header.UDPFields{
		SrcPort: srcIPPort.Port(),
		DstPort: dstIPPort.Port(),
		Length:  uint16(payloadLen + header.UDPMinimumSize),
	})
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(header.UDPMinimumSize+payloadLen))
	udpH.SetChecksum(^udpH.CalculateChecksum(pseudoCsum))
	return pkt
}

func udp6Packet(srcIPPort, dstIPPort netip.AddrPort, payloadLen int) *network.Packet {
	return udp6PacketMutateIPFields(srcIPPort, dstIPPort, payloadLen, nil)
}

func udp6PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, payloadLen int, ipFn func(*header.IPv6Fields)) *network.Packet {
	pkt := packetPool.Borrow()
	pkt.Offset = offset
	pkt.Size = 48 + int(payloadLen)
	b := pkt.Buf[:]

	ipv6H := header.IPv6(b[offset:])
	srcAs16 := srcIPPort.Addr().As16()
	dstAs16 := dstIPPort.Addr().As16()
	ipFields := &header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(srcAs16[:]),
		DstAddr:           tcpip.AddrFromSlice(dstAs16[:]),
		TransportProtocol: unix.IPPROTO_UDP,
		HopLimit:          64,
		PayloadLength:     uint16(payloadLen + header.UDPMinimumSize),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv6H.Encode(ipFields)
	udpH := header.UDP(b[offset+40:])
	udpH.Encode(&header.UDPFields{
		SrcPort: srcIPPort.Port(),
		DstPort: dstIPPort.Port(),
		Length:  uint16(payloadLen + header.UDPMinimumSize),
	})
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_UDP, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(header.UDPMinimumSize+payloadLen))
	udpH.SetChecksum(^udpH.CalculateChecksum(pseudoCsum))
	return pkt
}

func udp4Packet(srcIPPort, dstIPPort netip.AddrPort, payloadLen int) *network.Packet {
	return udp4PacketMutateIPFields(srcIPPort, dstIPPort, payloadLen, nil)
}

func tcp4PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv4Fields)) *network.Packet {
	pkt := packetPool.Borrow()
	pkt.Offset = offset
	pkt.Size = 40 + int(segmentSize)
	b := pkt.Buf[:]

	ipv4H := header.IPv4(b[offset:])
	srcAs4 := srcIPPort.Addr().As4()
	dstAs4 := dstIPPort.Addr().As4()
	ipFields := &header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(srcAs4[:]),
		DstAddr:     tcpip.AddrFromSlice(dstAs4[:]),
		Protocol:    unix.IPPROTO_TCP,
		TTL:         64,
		TotalLength: uint16(40 + segmentSize),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv4H.Encode(ipFields)
	tcpH := header.TCP(b[offset+20:])
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	ipv4H.SetChecksum(^ipv4H.CalculateChecksum())
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv4H.SourceAddress(), ipv4H.DestinationAddress(), uint16(20+segmentSize))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return pkt
}

func tcp4Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) *network.Packet {
	return tcp4PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

func tcp6PacketMutateIPFields(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32, ipFn func(*header.IPv6Fields)) *network.Packet {
	pkt := packetPool.Borrow()
	pkt.Offset = offset
	pkt.Size = 60 + int(segmentSize)
	b := pkt.Buf[:]

	ipv6H := header.IPv6(b[offset:])
	srcAs16 := srcIPPort.Addr().As16()
	dstAs16 := dstIPPort.Addr().As16()
	ipFields := &header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(srcAs16[:]),
		DstAddr:           tcpip.AddrFromSlice(dstAs16[:]),
		TransportProtocol: unix.IPPROTO_TCP,
		HopLimit:          64,
		PayloadLength:     uint16(segmentSize + 20),
	}
	if ipFn != nil {
		ipFn(ipFields)
	}
	ipv6H.Encode(ipFields)
	tcpH := header.TCP(b[offset+40:])
	tcpH.Encode(&header.TCPFields{
		SrcPort:    srcIPPort.Port(),
		DstPort:    dstIPPort.Port(),
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: 20,
		Flags:      flags,
		WindowSize: 3000,
	})
	pseudoCsum := header.PseudoHeaderChecksum(unix.IPPROTO_TCP, ipv6H.SourceAddress(), ipv6H.DestinationAddress(), uint16(20+segmentSize))
	tcpH.SetChecksum(^tcpH.CalculateChecksum(pseudoCsum))
	return pkt
}

func tcp6Packet(srcIPPort, dstIPPort netip.AddrPort, flags header.TCPFlags, segmentSize, seq uint32) *network.Packet {
	return tcp6PacketMutateIPFields(srcIPPort, dstIPPort, flags, segmentSize, seq, nil)
}

func flipTCP4Checksum(pkt *network.Packet) *network.Packet {
	at := VirtioNetHdrLen + 20 + 16 // 20 byte ipv4 header; tcp csum offset is 16
	pkt.Buf[at] ^= 0xFF
	pkt.Buf[at+1] ^= 0xFF
	return pkt
}

func flipUDP4Checksum(pkt *network.Packet) *network.Packet {
	at := VirtioNetHdrLen + 20 + 6 // 20 byte ipv4 header; udp csum offset is 6
	pkt.Buf[at] ^= 0xFF
	pkt.Buf[at+1] ^= 0xFF
	return pkt
}

func FuzzHandleGRO(f *testing.F) {
	pkt0 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)
	pkt1 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101)
	pkt2 := tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201)
	pkt3 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1)
	pkt4 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101)
	pkt5 := tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201)
	pkt6 := udp4Packet(ip4PortA, ip4PortB, 100)
	pkt7 := udp4Packet(ip4PortA, ip4PortB, 100)
	pkt8 := udp4Packet(ip4PortA, ip4PortC, 100)
	pkt9 := udp6Packet(ip6PortA, ip6PortB, 100)
	pkt10 := udp6Packet(ip6PortA, ip6PortB, 100)
	pkt11 := udp6Packet(ip6PortA, ip6PortC, 100)
	f.Add(pkt0.Bytes(), pkt1.Bytes(), pkt2.Bytes(), pkt3.Bytes(), pkt4.Bytes(), pkt5.Bytes(), pkt6.Bytes(), pkt7.Bytes(), pkt8.Bytes(), pkt9.Bytes(), pkt10.Bytes(), pkt11.Bytes(), true, offset)
	f.Fuzz(func(t *testing.T, pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11 []byte, canUDPGRO bool, offset int) {
		nic := &Interface{
			batchSize:   DefaultBatchSize,
			udpGSO:      canUDPGRO,
			tcpGROTable: newTCPGROTable(DefaultBatchSize),
			udpGROTable: newUDPGROTable(DefaultBatchSize),
		}

		pktBufs := [][]byte{pkt0, pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11}

		pkts := make([]*network.Packet, 0, len(pktBufs))
		for _, pktBuf := range pktBufs {
			pkt := packetPool.Borrow()
			pkt.Offset = offset
			pkt.Size = len(pktBuf)
			copy(pkt.Buf[offset:], pktBuf)
		}

		toWrite := make([]int, 0, len(pkts))
		toWrite, _ = nic.handleGRO(pkts, toWrite)
		require.Len(t, toWrite, len(toWrite))

		seenWriteI := make(map[int]bool)
		for _, writeI := range toWrite {
			require.GreaterOrEqual(t, writeI, 0)
			require.Less(t, writeI, len(pkts))
			require.False(t, seenWriteI[writeI], "duplicate toWrite value")
			seenWriteI[writeI] = true
		}
	})
}

func TestHandleGRO(t *testing.T) {
	tests := []struct {
		name        string
		pktsIn      []*network.Packet
		canUDPGRO   bool
		wantToWrite []int
		wantLens    []int
		wantErr     bool
	}{
		{
			"multiple protocols and flows",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // tcp4 flow 1
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp4Packet(ip4PortA, ip4PortC, 100),                         // udp4 flow 2
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // tcp4 flow 1
				tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201), // tcp4 flow 2
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),   // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101), // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201), // tcp6 flow 2
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
			},
			true,
			[]int{0, 1, 2, 4, 5, 7, 9},
			[]int{250, 238, 138, 150, 270, 170, 258},
			false,
		},
		{
			"multiple protocols and flows no UDP GRO",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // tcp4 flow 1
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp4Packet(ip4PortA, ip4PortC, 100),                         // udp4 flow 2
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // tcp4 flow 1
				tcp4Packet(ip4PortA, ip4PortC, header.TCPFlagAck, 100, 201), // tcp4 flow 2
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),   // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101), // tcp6 flow 1
				tcp6Packet(ip6PortA, ip6PortC, header.TCPFlagAck, 100, 201), // tcp6 flow 2
				udp4Packet(ip4PortA, ip4PortB, 100),                         // udp4 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
				udp6Packet(ip6PortA, ip6PortB, 100),                         // udp6 flow 1
			},
			false,
			[]int{0, 1, 2, 4, 5, 7, 8, 9, 10},
			[]int{250, 138, 138, 150, 270, 170, 138, 158, 158},
			false,
		},
		{
			"PSH interleaved",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),                     // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                   // v4 flow 1
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 301),                   // v4 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),                     // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 100, 101), // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 201),                   // v6 flow 1
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 301),                   // v6 flow 1
			},
			true,
			[]int{0, 2, 4, 6},
			[]int{250, 250, 270, 270},
			false,
		},
		{
			"coalesceItemInvalidCSum",
			[]*network.Packet{
				flipTCP4Checksum(tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1)), // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101),                 // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201),                 // v4 flow 1 seq 201 len 100
				flipUDP4Checksum(udp4Packet(ip4PortA, ip4PortB, 100)),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4Packet(ip4PortA, ip4PortB, 100),
			},
			true,
			[]int{0, 1, 3, 4},
			[]int{150, 250, 138, 238},
			false,
		},
		{
			"out of order",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101), // v4 flow 1 seq 101 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),   // v4 flow 1 seq 1 len 100
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 201), // v4 flow 1 seq 201 len 100
			},
			true,
			[]int{0},
			[]int{350},
			false,
		},
		{
			"unequal TTL",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TTL++
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.TTL++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{150, 150, 138, 138},
			false,
		},
		{
			"unequal ToS",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.TOS++
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.TOS++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{150, 150, 138, 138},
			false,
		},
		{
			"unequal flags more fragments set",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 1
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.Flags = 1
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{150, 150, 138, 138},
			false,
		},
		{
			"unequal flags DF set",
			[]*network.Packet{
				tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1),
				tcp4PacketMutateIPFields(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv4Fields) {
					fields.Flags = 2
				}),
				udp4Packet(ip4PortA, ip4PortB, 100),
				udp4PacketMutateIPFields(ip4PortA, ip4PortB, 100, func(fields *header.IPv4Fields) {
					fields.Flags = 2
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{150, 150, 138, 138},
			false,
		},
		{
			"ipv6 unequal hop limit",
			[]*network.Packet{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.HopLimit++
				}),
				udp6Packet(ip6PortA, ip6PortB, 100),
				udp6PacketMutateIPFields(ip6PortA, ip6PortB, 100, func(fields *header.IPv6Fields) {
					fields.HopLimit++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{170, 170, 158, 158},
			false,
		},
		{
			"ipv6 unequal traffic class",
			[]*network.Packet{
				tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1),
				tcp6PacketMutateIPFields(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 101, func(fields *header.IPv6Fields) {
					fields.TrafficClass++
				}),
				udp6Packet(ip6PortA, ip6PortB, 100),
				udp6PacketMutateIPFields(ip6PortA, ip6PortB, 100, func(fields *header.IPv6Fields) {
					fields.TrafficClass++
				}),
			},
			true,
			[]int{0, 1, 2, 3},
			[]int{170, 170, 158, 158},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nic := &Interface{
				batchSize:   DefaultBatchSize,
				udpGSO:      tt.canUDPGRO,
				tcpGROTable: newTCPGROTable(DefaultBatchSize),
				udpGROTable: newUDPGROTable(DefaultBatchSize),
			}

			toWrite := make([]int, 0, len(tt.pktsIn))
			toWrite, err := nic.handleGRO(tt.pktsIn, toWrite)
			if err != nil {
				if tt.wantErr {
					return
				}

				require.NoError(t, err)
			}

			require.Len(t, toWrite, len(tt.wantToWrite), "unexpected number of packets to write")

			for i, pktIndex := range tt.wantToWrite {
				require.Equal(t, tt.wantToWrite[i], toWrite[i])
				require.Equal(t, tt.wantLens[i], tt.pktsIn[pktIndex].Size)
			}
		})
	}
}

func TestPacketIsGROCandidate(t *testing.T) {
	tcp4 := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, 1).Bytes()
	tcp4TooShort := tcp4[:39]
	ip4InvalidHeaderLen := make([]byte, len(tcp4))
	copy(ip4InvalidHeaderLen, tcp4)
	ip4InvalidHeaderLen[0] = 0x46
	ip4InvalidProtocol := make([]byte, len(tcp4))
	copy(ip4InvalidProtocol, tcp4)
	ip4InvalidProtocol[9] = unix.IPPROTO_GRE

	tcp6 := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck, 100, 1).Bytes()
	tcp6TooShort := tcp6[:59]
	ip6InvalidProtocol := make([]byte, len(tcp6))
	copy(ip6InvalidProtocol, tcp6)
	ip6InvalidProtocol[6] = unix.IPPROTO_GRE

	udp4 := udp4Packet(ip4PortA, ip4PortB, 100).Bytes()
	udp4TooShort := udp4[:27]

	udp6 := udp6Packet(ip6PortA, ip6PortB, 100).Bytes()
	udp6TooShort := udp6[:47]

	tests := []struct {
		name      string
		b         []byte
		canUDPGRO bool
		want      groCandidateType
	}{
		{
			"tcp4",
			tcp4,
			true,
			tcp4GROCandidate,
		},
		{
			"tcp6",
			tcp6,
			true,
			tcp6GROCandidate,
		},
		{
			"udp4",
			udp4,
			true,
			udp4GROCandidate,
		},
		{
			"udp4 no support",
			udp4,
			false,
			notGROCandidate,
		},
		{
			"udp6",
			udp6,
			true,
			udp6GROCandidate,
		},
		{
			"udp6 no support",
			udp6,
			false,
			notGROCandidate,
		},
		{
			"udp4 too short",
			udp4TooShort,
			true,
			notGROCandidate,
		},
		{
			"udp6 too short",
			udp6TooShort,
			true,
			notGROCandidate,
		},
		{
			"tcp4 too short",
			tcp4TooShort,
			true,
			notGROCandidate,
		},
		{
			"tcp6 too short",
			tcp6TooShort,
			true,
			notGROCandidate,
		},
		{
			"invalid IP version",
			[]byte{0x00},
			true,
			notGROCandidate,
		},
		{
			"invalid IP header len",
			ip4InvalidHeaderLen,
			true,
			notGROCandidate,
		},
		{
			"ip4 invalid protocol",
			ip4InvalidProtocol,
			true,
			notGROCandidate,
		},
		{
			"ip6 invalid protocol",
			ip6InvalidProtocol,
			true,
			notGROCandidate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, packetIsGROCandidate(tt.b, tt.canUDPGRO))
		})
	}
}

func Test_udpPacketsCanCoalesce(t *testing.T) {
	udp4a := udp4Packet(ip4PortA, ip4PortB, 100)
	udp4b := udp4Packet(ip4PortA, ip4PortB, 100)
	udp4c := udp4Packet(ip4PortA, ip4PortB, 110)

	type args struct {
		pkt     []byte
		iphLen  uint8
		gsoSize uint16
		item    udpGROItem
		packets []*network.Packet
	}
	tests := []struct {
		name string
		args args
		want canCoalesce
	}{
		{
			"coalesceAppend equal gso",
			args{
				pkt:     udp4a.Bytes(),
				iphLen:  20,
				gsoSize: 100,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				packets: []*network.Packet{
					udp4a,
					udp4b,
				},
			},
			coalesceAppend,
		},
		{
			"coalesceAppend smaller gso",
			args{
				pkt:     udp4a.Bytes()[:udp4a.Size+offset-90],
				iphLen:  20,
				gsoSize: 10,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				packets: []*network.Packet{
					udp4a,
					udp4b,
				},
			},
			coalesceAppend,
		},
		{
			"coalesceUnavailable smaller gso previously appended",
			args{
				pkt:     udp4a.Bytes(),
				iphLen:  20,
				gsoSize: 100,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				packets: []*network.Packet{
					udp4c,
					udp4b,
				},
			},
			coalesceUnavailable,
		},
		{
			"coalesceUnavailable larger following smaller",
			args{
				pkt:     udp4c.Bytes(),
				iphLen:  20,
				gsoSize: 110,
				item: udpGROItem{
					gsoSize: 100,
					iphLen:  20,
				},
				packets: []*network.Packet{
					udp4a,
					udp4c,
				},
			},
			coalesceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, udpPacketsCanCoalesce(tt.args.pkt, tt.args.iphLen, tt.args.gsoSize, tt.args.item, tt.args.packets))
		})
	}
}
