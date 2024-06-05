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

type PacketPool struct {
	pool      *waitpool.WaitPool[*Packet]
	debug     bool
	borrowers sync.Map
}

// NewPacketPool creates a new packet pool with the given maximum number of
// packets.
func NewPacketPool(max int, debug bool) *PacketPool {
	var pp *PacketPool
	pp = &PacketPool{
		pool: waitpool.New(uint32(max), func() *Packet {
			return &Packet{
				pool: pp,
			}
		}),
		debug: debug,
	}
	return pp
}

func (p *PacketPool) Borrow() *Packet {
	pkt := p.pool.Get()
	pkt.Reset()

	if p.debug {
		pc, _, _, _ := runtime.Caller(1)
		if fn := runtime.FuncForPC(pc); fn != nil {
			pkt.borrowerName = fn.Name()
			if file, line := fn.FileLine(pc); file != "" {
				pkt.borrowerName += fmt.Sprintf(":%d", line)
			}
		} else {
			pkt.borrowerName = "unknown"
		}

		counter, _ := p.borrowers.LoadOrStore(pkt.borrowerName, &atomic.Int32{})
		counter.(*atomic.Int32).Add(1)
	}

	return pkt
}

func (p *PacketPool) Release(pkt *Packet) {
	p.pool.Put(pkt)

	if p.debug {
		counter, _ := p.borrowers.Load(pkt.borrowerName)
		counter.(*atomic.Int32).Add(-1)
	}
}

func (p *PacketPool) Count() int {
	return p.pool.Count()
}
