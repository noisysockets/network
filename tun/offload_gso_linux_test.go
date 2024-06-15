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
	"testing"

	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestHandleGSO(t *testing.T) {
	tests := []struct {
		name     string
		hdr      virtioNetHdr
		pktIn    *network.Packet
		wantLens []int
		wantErr  bool
	}{
		{
			"tcp4",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV4,
				gsoSize:    100,
				hdrLen:     40,
				csumStart:  20,
				csumOffset: 16,
			},
			tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{140, 140},
			false,
		},
		{
			"tcp6",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_TCPV6,
				gsoSize:    100,
				hdrLen:     60,
				csumStart:  40,
				csumOffset: 16,
			},
			tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 200, 1),
			[]int{160, 160},
			false,
		},
		{
			"udp4",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
				gsoSize:    100,
				hdrLen:     28,
				csumStart:  20,
				csumOffset: 6,
			},
			udp4Packet(ip4PortA, ip4PortB, 200),
			[]int{128, 128},
			false,
		},
		{
			"udp6",
			virtioNetHdr{
				flags:      unix.VIRTIO_NET_HDR_F_NEEDS_CSUM,
				gsoType:    unix.VIRTIO_NET_HDR_GSO_UDP_L4,
				gsoSize:    100,
				hdrLen:     48,
				csumStart:  40,
				csumOffset: 6,
			},
			udp6Packet(ip6PortA, ip6PortB, 200),
			[]int{148, 148},
			false,
		},
	}

	nic := &Interface{
		batchSize:  defaultBatchSize,
		vnetHdr:    true,
		packetPool: packetPool,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]*network.Packet, 0, defaultBatchSize)

			_ = tt.hdr.encode(tt.pktIn.Buf[tt.pktIn.Offset-VirtioNetHdrLen:])
			tt.pktIn.Offset -= VirtioNetHdrLen
			tt.pktIn.Size += VirtioNetHdrLen

			out, err := nic.handleGSO(tt.pktIn.Bytes(), out, offset)
			if err != nil {
				if tt.wantErr {
					return
				}
				require.NoError(t, err)
			}
			require.Len(t, out, len(tt.wantLens))
			for i := range tt.wantLens {
				require.Equal(t, tt.wantLens[i], out[i].Size)
			}
		})
	}
}
