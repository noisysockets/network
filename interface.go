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

	// Name returns the name of the interface.
	Name() string

	// MTU returns the MTU of the interface.
	MTU() int

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call.
	BatchSize() int

	// Read one or more packets from the interface (without any additional headers).
	// On a successful read it returns the number of packets read. A nonzero offset
	// can be used to instruct the interface on where to begin reading into each
	// packet buffer (useful for reserving space for headers). Ownership of the
	// packets is not transferred to the interface.
	Read(ctx context.Context, packets []*Packet, offset int) (n int, err error)

	// Write one or more packets to the interface (without any additional headers).
	// On a successful write it returns the number of packets written. Ownership
	// of the packets is not transferred to the interface.
	Write(ctx context.Context, packets []*Packet) (int, error)
}
