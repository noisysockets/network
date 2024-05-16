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
	stdnet "net"
)

type pipeEndpoint struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mtu       int
	batchSize int
	recvCh    chan []byte
	sendCh    chan []byte
}

// Pipe creates a pair of connected interfaces that can be used to simulate a
// network connection.
func Pipe(mtu, batchSize int) (Interface, Interface) {
	ctx, cancel := context.WithCancel(context.Background())

	// Creating buffered channels
	aToB := make(chan []byte, batchSize)
	bToA := make(chan []byte, batchSize)

	go func() {
		<-ctx.Done()

		close(aToB)
		close(bToA)
	}()

	a := &pipeEndpoint{
		ctx:       ctx,
		cancel:    cancel,
		mtu:       mtu,
		batchSize: batchSize,
		recvCh:    bToA,
		sendCh:    aToB,
	}

	b := &pipeEndpoint{
		ctx:       ctx,
		cancel:    cancel,
		mtu:       mtu,
		batchSize: batchSize,
		recvCh:    aToB,
		sendCh:    bToA,
	}

	return a, b
}

func (p *pipeEndpoint) Name() (string, error) {
	return "PipeInterface", nil
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
			case <-p.ctx.Done():
				return n, stdnet.ErrClosed
			case packet := <-p.recvCh:
				processPacket(i, packet)
			}
		} else {
			select {
			case <-ctx.Done():
				return n, ctx.Err()
			case <-p.ctx.Done():
				return n, stdnet.ErrClosed
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
		select {
		case <-ctx.Done():
			return i, ctx.Err()
		case <-p.ctx.Done():
			return i, stdnet.ErrClosed
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
