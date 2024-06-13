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
	"errors"
	"os"
	"testing"

	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
)

func TestSplice(t *testing.T) {
	packetPool := network.NewPacketPool(32, false)

	nicA, nicB := network.Pipe(&network.PipeConfiguration{
		PacketPool: packetPool,
	})
	nicC, nicD := network.Pipe(&network.PipeConfiguration{
		PacketPool: packetPool,
	})
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
		require.NoError(t, nicC.Close())
		require.NoError(t, nicD.Close())
	})

	ctx := context.Background()
	go func() {
		if err := network.Splice(ctx, nicB, nicC, nil); err != nil && !errors.Is(err, os.ErrClosed) {
			panic(err)
		}
	}()

	// Write to nicA, read from nicD
	{
		pkt := packetPool.Borrow()
		pkt.Size = copy(pkt.Buf[:], []byte("hello"))
		t.Cleanup(pkt.Release)

		err := nicA.Write(ctx, []*network.Packet{pkt})
		require.NoError(t, err)

		packets := make([]*network.Packet, 0, nicD.BatchSize())
		packets, err = nicD.Read(ctx, packets, 0)
		require.NoError(t, err)

		require.Equal(t, 1, len(packets))
		require.Equal(t, "hello", string(packets[0].Bytes()))

		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}

	// Write to nicD, read from nicA
	{
		pkt := packetPool.Borrow()
		pkt.Size = copy(pkt.Buf[:], []byte("world"))
		t.Cleanup(pkt.Release)

		err := nicD.Write(ctx, []*network.Packet{pkt})
		require.NoError(t, err)

		packets := make([]*network.Packet, 0, nicA.BatchSize())
		packets, err = nicA.Read(ctx, packets, 0)
		require.NoError(t, err)

		require.Equal(t, 1, len(packets))
		require.Equal(t, "world", string(packets[0].Bytes()))

		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}
}
