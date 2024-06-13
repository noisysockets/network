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
	"fmt"

	"github.com/noisysockets/netutil/defaults"
	"golang.org/x/sync/errgroup"
)

type SpliceConfiguration struct {
	// PacketWriteOffset is an optional hint to write outbound packet data at a
	// specific offset inside the buffer. This is a performance hint for
	// WireGuard (and other protocols that need to add their own headers).
	PacketWriteOffset int
}

// Splice splices (bidirectional copy) two network interfaces together.
func Splice(ctx context.Context, nicA, nicB Interface, conf *SpliceConfiguration) error {
	conf, err := defaults.WithDefaults(conf, &SpliceConfiguration{})
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return copyPackets(ctx, nicA, nicB, conf.PacketWriteOffset)
	})

	g.Go(func() error {
		return copyPackets(ctx, nicB, nicA, conf.PacketWriteOffset)
	})

	return g.Wait()
}

func copyPackets(ctx context.Context, dst, src Interface, packetWriteOffset int) error {
	batchSize := dst.BatchSize()
	packets := make([]*Packet, 0, batchSize)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fmt.Println("reading packets")

		var err error
		packets, err = src.Read(ctx, packets, packetWriteOffset)
		if err != nil {
			return err
		}

		fmt.Println("writing packets", len(packets))

		if err := dst.Write(ctx, packets); err != nil {
			return err
		}

		packets = packets[:0]
	}
}
