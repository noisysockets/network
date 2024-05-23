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
	nicA, nicB := network.Pipe(1500, 16)
	t.Cleanup(func() {
		require.NoError(t, nicA.Close())
		require.NoError(t, nicB.Close())
	})

	sizes := make([]int, nicA.BatchSize())

	bufs := make([][]byte, nicA.BatchSize())
	for i := 0; i < nicA.BatchSize(); i++ {
		bufs[i] = make([]byte, nicA.MTU())
	}

	// Send a packet from A to B.
	// Make sure B receives it.

	ctx := context.Background()
	n, err := nicA.Write(ctx, [][]byte{[]byte("hello")}, []int{5}, 0)
	require.NoError(t, err)

	require.Equal(t, 1, n)

	n, err = nicB.Read(ctx, bufs, sizes, 0)
	require.NoError(t, err)

	require.Equal(t, 1, n)
	require.Equal(t, 5, sizes[0])
	require.Equal(t, "hello", string(bufs[0][:5]))

	// Send a packet from B to A.
	// Make sure A receives it.

	n, err = nicB.Write(ctx, [][]byte{[]byte("world")}, []int{5}, 0)
	require.NoError(t, err)

	require.Equal(t, 1, n)

	n, err = nicA.Read(ctx, bufs, sizes, 0)
	require.NoError(t, err)

	require.Equal(t, 1, n)
	require.Equal(t, 5, sizes[0])
	require.Equal(t, "world", string(bufs[0][:5]))
}
