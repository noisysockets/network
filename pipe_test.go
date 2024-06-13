// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network_test

import (
	"context"
	"testing"

	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
)

func TestPipe(t *testing.T) {
	packetPool := network.NewPacketPool(32, false)

	nicA, nicB := network.Pipe(&network.PipeConfiguration{
		PacketPool: packetPool,
	})
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
	})

	// Send a packet from A to B.
	// Make sure B receives it.

	pkt := packetPool.Borrow()
	pkt.Size = copy(pkt.Buf[:], []byte("hello"))
	t.Cleanup(pkt.Release)

	ctx := context.Background()
	err := nicA.Write(ctx, []*network.Packet{pkt})
	require.NoError(t, err)

	{
		packets := make([]*network.Packet, 0, nicB.BatchSize())
		packets, err = nicB.Read(ctx, packets, 0)
		require.NoError(t, err)
		t.Cleanup(func() {
			for i, pkt := range packets {
				pkt.Release()
				packets[i] = nil
			}
		})

		require.Equal(t, "hello", string(packets[0].Bytes()))
	}

	// Send a packet from B to A.
	// Make sure A receives it.

	pkt = packetPool.Borrow()
	pkt.Size = copy(pkt.Buf[:], []byte("world"))
	t.Cleanup(pkt.Release)

	err = nicB.Write(ctx, []*network.Packet{pkt})
	require.NoError(t, err)

	{
		packets := make([]*network.Packet, 0, nicA.BatchSize())
		packets, err = nicA.Read(ctx, packets, 0)
		require.NoError(t, err)
		t.Cleanup(func() {
			for i, pkt := range packets {
				pkt.Release()
				packets[i] = nil
			}
		})

		require.Equal(t, "world", string(packets[0].Bytes()))
	}
}
