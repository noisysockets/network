// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from wireguard-go,
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package network

import (
	"context"
	"io"
)

// Interface is a network interface.
type Interface interface {
	io.Closer

	// MTU returns the Maximum Transmission Unit of the interface.
	MTU() (int, error)

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call.
	BatchSize() int

	// Read one or more packets from the interface (without any additional headers).
	// On a successful read it returns a slice of packets of up-to length batchSize.
	// The caller is responsible for releasing the packets back to the pool. The
	// caller can optionally supply an unallocated packets slice (eg. from a
	// previous call to Read()) that will be used to store the read packets.
	// This allows avoiding allocating a new packets slice on each read.
	Read(ctx context.Context, packets []*Packet, offset int) ([]*Packet, error)

	// Write one or more packets to the interface (without any additional headers).
	// Ownership of the packets is transferred to the interface and must not be
	// accessed after a write operation.
	Write(ctx context.Context, packets []*Packet) error
}
