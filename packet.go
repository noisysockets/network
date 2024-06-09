// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

const (
	// MaxPacketSize is the maximum size of an IP packet.
	MaxPacketSize = 65535
)

// Packet represents an IP packet.
type Packet struct {
	// Buf is the buffer containing the packet data.
	Buf [MaxPacketSize]byte
	// Offset is the offset inside the buffer where the packet data starts.
	Offset int
	// Size is the size of the packet data.
	Size int
	// pool is the pool from which the packet was borrowed.
	pool *PacketPool
	// when debugPacketPool is true, borrowerName is the name of the function
	// that borrowed the packet.
	borrowerName string
}

// Release returns the packet to its pool.
func (p *Packet) Release() {
	p.pool.Release(p)
}

// Reset resets the packet.
func (p *Packet) Reset() {
	p.Offset = 0
	p.Size = 0
}

// Bytes returns the packet data as a byte slice.
func (p *Packet) Bytes() []byte {
	return p.Buf[p.Offset : p.Offset+p.Size]
}

// MoveOffset moves the packet data to a new offset inside the buffer.
// This can be a potentially expensive operation.
func (p *Packet) MoveOffset(offset int) {
	if p.Offset != offset {
		copy(p.Buf[offset:], p.Bytes())
		p.Offset = offset
	}
}
