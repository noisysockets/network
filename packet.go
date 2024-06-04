// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import "github.com/noisysockets/netutil/waitpool"

const (
	// MaxPacketSize is the maximum size of an IP packet.
	MaxPacketSize = 65535
	// MaxBufferedPackets is the maximum number of outstanding packet buffers.
	// This is used to limit the number of packets that can be in flight at any
	// given time. This value corresponds to approximately 64MB of memory.
	MaxBufferedPackets = 1024
)

// Packet represents an IP packet.
type Packet struct {
	// Buf is the buffer containing the packet data.
	Buf [MaxPacketSize]byte
	// Offset is the offset inside the buffer where the packet data starts.
	Offset int
	// Size is the size of the packet data.
	Size int
}

// packetPool is a pool of packet buffers.
var packetPool = waitpool.New(MaxBufferedPackets, func() *Packet {
	return &Packet{}
})

// NewPacket creates a new packet.
func NewPacket() *Packet {
	pkt := packetPool.Get()
	pkt.Reset()
	return pkt
}

// Reset resets the packet.
func (p *Packet) Reset() {
	p.Offset = 0
	p.Size = 0
}

// Clone create a caller-owned copy of the packet.
func (p *Packet) Clone() *Packet {
	cloned := NewPacket()
	cloned.Size = copy(cloned.Buf[:], p.Buf[p.Offset:p.Offset+p.Size])
	return cloned
}

// Release returns the packet to the pool.
func (p *Packet) Release() {
	packetPool.Put(p)
}
