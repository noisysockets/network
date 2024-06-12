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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/noisysockets/netstack/pkg/tcpip"
	"github.com/noisysockets/netstack/pkg/tcpip/checksum"
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/netstack/pkg/tcpip/transport/tcp"
	"github.com/noisysockets/network"
	"golang.org/x/sys/unix"
)

func (nic *Interface) handleGSO(in []byte, packets []*network.Packet, offset int) ([]*network.Packet, error) {
	var hdr virtioNetHdr
	if err := hdr.decode(in); err != nil {
		return packets, err
	}
	in = in[VirtioNetHdrLen:]
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_NONE {
		if hdr.flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			// This means CHECKSUM_PARTIAL in skb context. We are responsible
			// for computing the checksum starting at hdr.csumStart and placing
			// at hdr.csumOffset.
			if err := gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset); err != nil {
				return packets, err
			}
		}
		if len(in) > network.MaxPacketSize-offset {
			return packets, fmt.Errorf("read len %d overflows bufs element len %d", len(in), network.MaxPacketSize-offset)
		}
		pkt := nic.packetPool.Borrow()
		pkt.Offset = offset
		pkt.Size = copy(pkt.Buf[offset:], in)
		packets = append(packets, pkt)
		return packets, nil
	}
	if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		return packets, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV4 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return packets, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_TCPV6 && hdr.gsoType != unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
			return packets, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return packets, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// Don't trust hdr.hdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// csumStart, which is synonymous for IP header length.
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_UDP_L4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(in) <= int(hdr.csumStart+12) {
			return packets, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < header.TCPMinimumSize || tcpHLen > header.TCPHeaderMaximumSize {
			// A TCP header must be between 20 and 60 bytes in length.
			return packets, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(in) < int(hdr.hdrLen) {
		return packets, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}

	if hdr.hdrLen < hdr.csumStart {
		return packets, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	if cSumAt+1 >= len(in) {
		return packets, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	return nic.gsoSplit(in, hdr, packets, offset, ipVersion == 6)
}

func (nic *Interface) gsoSplit(in []byte, hdr virtioNetHdr, packets []*network.Packet, offset int, isV6 bool) ([]*network.Packet, error) {
	iphLen := int(hdr.csumStart)
	srcAddrAt := ipv6SrcAddrOffset
	addrSize := 16
	if !isV6 {
		in[10], in[11] = 0, 0 // clear ipv4 header checksum
		srcAddrAt = ipv4SrcAddrOffset
		addrSize = 4
	}
	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	in[transportCsumAt], in[transportCsumAt+1] = 0, 0 // clear tcp/udp checksum
	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV4 || hdr.gsoType == unix.VIRTIO_NET_HDR_GSO_TCPV6 {
		protocol = unix.IPPROTO_TCP
		firstTCPSeqNum = binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	} else {
		protocol = unix.IPPROTO_UDP
	}
	nextSegmentDataAt := int(hdr.hdrLen)
	i := 0
	for ; nextSegmentDataAt < len(in); i++ {
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen

		pkt := nic.packetPool.Borrow()
		pkt.Offset = offset
		pkt.Size = totalLen
		packets = append(packets, pkt)

		out := pkt.Bytes()

		copy(out, in[:iphLen])
		if !isV6 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum.Checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		// copy transport header
		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])

		if protocol == unix.IPPROTO_TCP {
			// set TCP seq and adjust TCP flags
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(in) {
				// FIN and PSH should only be set on last segment
				clearFlags := uint8(header.TCPFlagFin | header.TCPFlagPsh)
				out[hdr.csumStart+header.TCPFlagsOffset] &^= clearFlags
			}
		} else {
			// set UDP header len
			binary.BigEndian.PutUint16(out[hdr.csumStart+4:], uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		// payload
		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		// transport checksum
		srcAddr := in[srcAddrAt : srcAddrAt+addrSize]
		dstAddr := in[srcAddrAt+addrSize : srcAddrAt+addrSize*2]
		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSumNoFold := header.PseudoHeaderChecksum(
			tcp.ProtocolNumber,
			tcpip.AddrFromSlice(srcAddr),
			tcpip.AddrFromSlice(dstAddr),
			lenForPseudo)

		transportCSum := ^checksum.Checksum(out[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], transportCSum)

		nextSegmentDataAt += int(hdr.gsoSize)
	}

	return packets, nil
}

func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := cSumStart + cSumOffset
	// The initial value at the checksum offset should be summed with the
	// checksum we compute. This is typically the pseudo-header checksum.
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	in[cSumAt], in[cSumAt+1] = 0, 0
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum.Checksum(in[cSumStart:], initial))
	return nil
}
