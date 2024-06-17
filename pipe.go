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
	"context"
	"os"
	"sync/atomic"

	"github.com/noisysockets/util/defaults"
	"github.com/noisysockets/util/ptr"
)

// PipeConfiguration is the configuration for a pipe.
type PipeConfiguration struct {
	// MTU is the maximum transmission unit of the pipe.
	// If not specified, a default MTU of 1500 will be used.
	MTU *int
	// BatchSize is the maximum number of packets that can be read or written at
	// once. If not specified, a default batch size of 16 will be used.
	BatchSize *int
	// PacketPool is the pool from which packets are borrowed.
	// If not specified, an unbounded pool will be created.
	PacketPool *PacketPool
}

// Pipe creates a pair of connected interfaces that can be used to simulate a
// network connection. This is similar to a linux veth device.
func Pipe(conf *PipeConfiguration) (Interface, Interface) {
	conf, err := defaults.WithDefaults(conf, &PipeConfiguration{
		MTU:       ptr.To(1500),
		BatchSize: ptr.To(16),
	})
	if err != nil {
		panic(err)
	}

	if conf.PacketPool == nil {
		conf.PacketPool = NewPacketPool(0, false)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Creating buffered channels
	aToB := make(chan *Packet, *conf.BatchSize)
	bToA := make(chan *Packet, *conf.BatchSize)

	a := &pipeEndpoint{
		cancel:     cancel,
		mtu:        *conf.MTU,
		batchSize:  *conf.BatchSize,
		packetPool: conf.PacketPool,
		recvCh:     bToA,
		sendCh:     aToB,
	}

	b := &pipeEndpoint{
		cancel:     cancel,
		mtu:        *conf.MTU,
		batchSize:  *conf.BatchSize,
		packetPool: conf.PacketPool,
		recvCh:     aToB,
		sendCh:     bToA,
	}

	go func() {
		<-ctx.Done()

		// Signal that we are closing.
		a.sendClosing.Store(true)
		b.sendClosing.Store(true)

		// Drain the channels as they might be blocked on a send.
		for {
			select {
			case <-a.sendCh:
				continue
			default:
			}
			close(a.sendCh)
			break
		}

		for {
			select {
			case <-b.sendCh:
				continue
			default:
			}
			close(b.sendCh)
			break
		}
	}()

	return a, b
}

type pipeEndpoint struct {
	cancel      context.CancelFunc
	mtu         int
	batchSize   int
	packetPool  *PacketPool
	sendClosing atomic.Bool
	recvCh      chan *Packet
	sendCh      chan *Packet
}

func (p *pipeEndpoint) MTU() (int, error) {
	return p.mtu, nil
}

func (p *pipeEndpoint) BatchSize() int {
	return p.batchSize
}

func (p *pipeEndpoint) Read(ctx context.Context, packets []*Packet, offset int) ([]*Packet, error) {
	if len(packets) != 0 {
		packets = packets[:0]
	}

	for i := 0; i < p.batchSize; i++ {
		if i == 0 {
			// Read at least one packet.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case pkt, ok := <-p.recvCh:
				if !ok {
					// No more packets available.
					return nil, os.ErrClosed
				}

				pkt.MoveOffset(offset)
				packets = append(packets, pkt)
			}
		} else {
			select {
			case <-ctx.Done():
				return packets, ctx.Err()
			case pkt, ok := <-p.recvCh:
				if !ok {
					// No more packets available.
					return packets, os.ErrClosed
				}

				pkt.MoveOffset(offset)
				packets = append(packets, pkt)
			default:
				// No more packets available.
				return packets, nil
			}
		}
	}

	return packets, nil
}

func (p *pipeEndpoint) Write(ctx context.Context, packets []*Packet) (err error) {
	for i := range packets {
		pkt := packets[i]

		if p.sendClosing.Load() {
			continue
		}

		select {
		case <-ctx.Done():
			pkt.Release()
			packets[i] = nil
			return ctx.Err()
		case p.sendCh <- pkt:
			// packet sent successfully
		}
	}
	return
}

func (p *pipeEndpoint) Close() error {
	p.cancel()
	return nil
}
