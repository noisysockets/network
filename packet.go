// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import (
	"fmt"
	"runtime"
	"sync"

	"sync/atomic"

	"github.com/noisysockets/netutil/waitpool"
)

const (
	// MaxPacketSize is the maximum size of an IP packet.
	MaxPacketSize = 65535
	// MaxBufferedPackets is the maximum number of outstanding packet buffers.
	// This is used to limit the number of packets that can be in flight at any
	// given time. This value corresponds to approximately 256MB of memory.
	MaxBufferedPackets = 4096
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
	pool *waitpool.WaitPool[*Packet]
	// when debugPacketPool is true, borrowerName is the name of the function
	// that borrowed the packet.
	borrowerName string
}

// DefaultPacketPool is the default pool of packet buffers.
var DefaultPacketPool *waitpool.WaitPool[*Packet]

func init() {
	DefaultPacketPool = waitpool.New(MaxBufferedPackets, func() *Packet {
		return &Packet{
			pool: DefaultPacketPool,
		}
	})
}

// DefaultPacketPoolBorrowers is a map of function names to the number of packets
// borrowed by that function. This is exposed for debugging purposes.
var DefaultPacketPoolBorrowers sync.Map

// NewPacket borrows a new packet from the default pool.
func NewPacket() *Packet {
	pkt := DefaultPacketPool.Get()
	pkt.Reset()

	if networkDebug {
		pc, _, _, _ := runtime.Caller(1)
		if fn := runtime.FuncForPC(pc); fn != nil {
			pkt.borrowerName = fn.Name()
			if file, line := fn.FileLine(pc); file != "" {
				pkt.borrowerName += fmt.Sprintf(":%d", line)
			}
		} else {
			pkt.borrowerName = "unknown"
		}

		// Atomically increment the number of packets borrowed by the caller.
		counter, _ := DefaultPacketPoolBorrowers.LoadOrStore(pkt.borrowerName, &atomic.Int32{})
		counter.(*atomic.Int32).Add(1)
	}

	return pkt
}

// PacketFromBytes creates a new packet from a byte slice. The byte slice is
// copied and can be safely modified after the call.
func PacketFromBytes(b []byte) *Packet {
	pkt := NewPacket()
	pkt.Size = copy(pkt.Buf[:], b)
	return pkt
}

// Release returns the packet to its pool.
func (p *Packet) Release() {
	DefaultPacketPool.Put(p)

	if networkDebug {
		counter, _ := DefaultPacketPoolBorrowers.Load(p.borrowerName)
		counter.(*atomic.Int32).Add(-1)
	}
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

// Bytes returns the packet data as a byte slice.
func (p *Packet) Bytes() []byte {
	return p.Buf[p.Offset : p.Offset+p.Size]
}
