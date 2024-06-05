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
)

type pipeEndpoint struct {
	name        string
	cancel      context.CancelFunc
	mtu         int
	batchSize   int
	sendClosing atomic.Bool
	recvCh      chan *Packet
	sendCh      chan *Packet
}

// Pipe creates a pair of connected interfaces that can be used to simulate a
// network connection. This is similar to a linux veth device.
func Pipe(mtu, batchSize int) (Interface, Interface) {
	ctx, cancel := context.WithCancel(context.Background())

	// Creating buffered channels
	aToB := make(chan *Packet, batchSize)
	bToA := make(chan *Packet, batchSize)

	a := &pipeEndpoint{
		name:      "pipe0",
		cancel:    cancel,
		mtu:       mtu,
		batchSize: batchSize,
		recvCh:    bToA,
		sendCh:    aToB,
	}

	b := &pipeEndpoint{
		name:      "pipe1",
		cancel:    cancel,
		mtu:       mtu,
		batchSize: batchSize,
		recvCh:    aToB,
		sendCh:    bToA,
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

func (p *pipeEndpoint) Name() string {
	return p.name
}

func (p *pipeEndpoint) MTU() int {
	return p.mtu
}

func (p *pipeEndpoint) BatchSize() int {
	return p.batchSize
}

func (p *pipeEndpoint) Read(ctx context.Context, packets []*Packet, offset int) (n int, err error) {
	processPacket := func(i int, pkt *Packet) {
		defer pkt.Release()

		packets[i].Reset()
		packets[i].Size = copy(packets[i].Buf[offset:], pkt.Bytes())
		packets[i].Offset = offset
		n++
	}

	for i := range packets {
		if i == 0 {
			// Read at least one packet.
			select {
			case <-ctx.Done():
				return n, ctx.Err()
			case pkt, ok := <-p.recvCh:
				if !ok {
					// No more packets available.
					return 0, os.ErrClosed
				}

				processPacket(i, pkt)
			}
		} else {
			select {
			case <-ctx.Done():
				return n, ctx.Err()
			case pkt, ok := <-p.recvCh:
				if !ok {
					// No more packets available.
					return n, os.ErrClosed
				}

				processPacket(i, pkt)
			default:
				// No more packets available.
				return n, nil
			}
		}
	}

	return n, nil
}

func (p *pipeEndpoint) Write(ctx context.Context, packets []*Packet) (n int, err error) {
	for _, pkt := range packets {
		if p.sendClosing.Load() {
			continue
		}

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case p.sendCh <- pkt.Clone():
			// packet sent successfully
			n++
		}
	}
	return
}

func (p *pipeEndpoint) Close() error {
	p.cancel()
	return nil
}
