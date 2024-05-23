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
	"sync/atomic"
)

type pipeEndpoint struct {
	name        string
	cancel      context.CancelFunc
	mtu         int
	batchSize   int
	sendClosing atomic.Bool
	recvCh      chan []byte
	sendCh      chan []byte
}

// Pipe creates a pair of connected interfaces that can be used to simulate a
// network connection. This is similar to a linux veth device.
func Pipe(mtu, batchSize int) (Interface, Interface) {
	ctx, cancel := context.WithCancel(context.Background())

	// Creating buffered channels
	aToB := make(chan []byte, batchSize)
	bToA := make(chan []byte, batchSize)

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

func (p *pipeEndpoint) Read(ctx context.Context, bufs [][]byte, sizes []int, offset int) (n int, err error) {
	processPacket := func(idx int, packet []byte) {
		copy(bufs[idx][offset:], packet)
		sizes[idx] = len(packet)
		n++
	}

	for i := range bufs {
		if i == 0 {
			// Read at least one packet.
			select {
			case <-ctx.Done():
				return n, ctx.Err()
			case packet := <-p.recvCh:
				processPacket(i, packet)
			}
		} else {
			select {
			case <-ctx.Done():
				return n, ctx.Err()
			case packet := <-p.recvCh:
				processPacket(i, packet)
			default:
				// No more packets available.
				return n, nil
			}
		}
	}

	return n, nil
}

func (p *pipeEndpoint) Write(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, buf := range bufs {
		packet := make([]byte, sizes[i])
		copy(packet, buf[offset:offset+sizes[i]])

		if p.sendClosing.Load() {
			return i, nil
		}

		select {
		case <-ctx.Done():
			return i, ctx.Err()
		case p.sendCh <- packet:
			// packet sent successfully
		}
	}
	return len(bufs), nil
}

func (p *pipeEndpoint) Close() error {
	p.cancel()
	return nil
}
