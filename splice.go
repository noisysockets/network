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

	"golang.org/x/sync/errgroup"
)

// Splice splices (bidirectional copy) two network interfaces together.
func Splice(ctx context.Context, nicA, nicB Interface) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return copyPackets(ctx, nicA, nicB)
	})

	g.Go(func() error {
		return copyPackets(ctx, nicB, nicA)
	})

	return g.Wait()
}

func copyPackets(ctx context.Context, dst, src Interface) error {
	batchSize := dst.BatchSize()
	packets := make([]*Packet, 0, batchSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var err error
		packets, err = src.Read(ctx, packets, 0)
		if err != nil {
			return err
		}

		for written := 0; written < len(packets); {
			n, err := dst.Write(ctx, packets)
			written += n
			packets = packets[n:]

			if err != nil {
				for i, pkt := range packets {
					pkt.Release()
					packets[i] = nil
				}

				return err
			}
		}

		packets = packets[:0]
	}
}
