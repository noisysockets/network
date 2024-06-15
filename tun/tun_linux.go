//go:build linux

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

// Package tun provides a TUN device implementation for noisysockets.
package tun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/noisysockets/netutil/defaults"
	"github.com/noisysockets/netutil/ptr"
	"github.com/noisysockets/network"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var _ network.Interface = (*Interface)(nil)

// Configuration is the configuration for a TUN device.
type Configuration struct {
	// BatchSize is the number of packets to read in a single syscall.
	// This is only used when the TUN device supports IFF_VNET_HDR.
	BatchSize *int
	// MTU is the maximum transmission unit of the TUN device.
	// If MTU is nil, DefaultMTU is used.
	MTU *int
	// PacketPool is the pool from which packets are borrowed.
	// If not specified, an unbounded pool will be created.
	PacketPool *network.PacketPool
	// Fd is optionally the file descriptor of an existing TUN device.
	Fd *int
	// Unmanaged is a flag to indicate if the TUN device is unmanaged
	// eg. we are not responsible for setting the MTU or bringing the
	// link up.
	Unmanaged bool
}

// Interface is a TUN network interface implementation for linux.
type Interface struct {
	logger      *slog.Logger
	name        string
	tunFile     *os.File
	packetPool  *network.PacketPool
	initalMTU   int
	batchSize   int
	vnetHdr     bool
	udpGSO      bool
	unmanaged   bool
	readOpMu    sync.Mutex // readOpMu guards vnetReadBuf
	vnetReadBuf [VirtioNetHdrLen + network.MaxPacketSize]byte
	writeOpMu   sync.Mutex // writeOpMu guards toWrite, tcpGROTable, udpGROTable
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
	toWrite     []int
}

// Create creates a new TUN device with the specified configuration.
func Create(ctx context.Context, logger *slog.Logger, name string, conf *Configuration) (network.Interface, error) {
	conf, err := defaults.WithDefaults(conf, &Configuration{
		BatchSize:  ptr.To(128),
		MTU:        ptr.To(1500),
		PacketPool: network.NewPacketPool(0, false),
	})
	if err != nil {
		return nil, err
	}

	var fd int
	if conf.Fd != nil {
		fd = *conf.Fd
	} else {
		fd, err = unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, errors.New("TUN/TAP device not found (missing CONFIG_TUN)")
			}
			return nil, err
		}
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, err
	}

	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return nil, err
	}

	var batchSize int
	var vnetHdr, udpGSO bool
	if ifr.Uint16()&unix.IFF_VNET_HDR != 0 {
		const (
			// TODO: support TSO with ECN bits
			tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
			tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
		)

		// tunTCPOffloads were added in Linux v2.6. We require their support
		// if IFF_VNET_HDR is set.
		if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, tunTCPOffloads); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("failed to set offloads for %s: %w", name, err)
		}

		// tunUDPOffloads were added in Linux v6.2. We do not return an
		// error if they are unsupported at runtime.
		udpGSO = unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) == nil

		vnetHdr = true
		batchSize = *conf.BatchSize
	} else {
		batchSize = 1
	}

	logger.Debug("Created TUN interface",
		slog.String("name", name),
		slog.Bool("vnetHdr", vnetHdr),
		slog.Bool("udpGSO", udpGSO),
		slog.Int("batchSize", batchSize))

	if !conf.Unmanaged {
		link, err := netlink.LinkByName(name)
		if err != nil {
			return nil, fmt.Errorf("failed to find link %s: %w", name, err)
		}

		if err := netlink.LinkSetMTU(link, *conf.MTU); err != nil {
			return nil, fmt.Errorf("failed to set MTU for %s: %w", name, err)
		}

		if err := netlink.LinkSetUp(link); err != nil {
			return nil, fmt.Errorf("failed to set %s up: %w", name, err)
		}
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing
	// it to netpoll.
	tunFile := os.NewFile(uintptr(fd), "/dev/net/tun")

	return &Interface{
		logger:      logger,
		name:        name,
		tunFile:     tunFile,
		packetPool:  conf.PacketPool,
		initalMTU:   *conf.MTU,
		batchSize:   batchSize,
		vnetHdr:     vnetHdr,
		udpGSO:      udpGSO,
		unmanaged:   conf.Unmanaged,
		tcpGROTable: newTCPGROTable(batchSize),
		udpGROTable: newUDPGROTable(batchSize),
		toWrite:     make([]int, 0, batchSize),
	}, nil
}

func (nic *Interface) Close() error {
	return nic.tunFile.Close()
}

func (nic *Interface) Read(ctx context.Context, packets []*network.Packet, offset int) ([]*network.Packet, error) {
	nic.readOpMu.Lock()
	defer nic.readOpMu.Unlock()

	if len(packets) > 0 {
		packets = packets[:0]
	}

	var pkt *network.Packet
	var readInto []byte

	if !nic.vnetHdr {
		pkt = nic.packetPool.Borrow()
		pkt.Offset = offset
		readInto = pkt.Buf[offset:]
	} else {
		readInto = nic.vnetReadBuf[:]
	}

	for {
		err := nic.tunFile.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			return packets, err
		}

		n, err := nic.tunFile.Read(readInto)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-ctx.Done():
					return packets, ctx.Err()
				default:
					continue
				}
			}
			if errors.Is(err, syscall.EBADFD) {
				return packets, os.ErrClosed
			}
			return packets, err
		}

		if nic.vnetHdr {
			return nic.handleGSO(readInto[:n], packets, offset)
		} else {
			pkt.Size = n
			packets = append(packets, pkt)
			return packets, nil
		}
	}
}

func (nic *Interface) Write(ctx context.Context, packets []*network.Packet) error {
	nic.writeOpMu.Lock()
	defer func() {
		nic.tcpGROTable.reset()
		nic.udpGROTable.reset()
		nic.writeOpMu.Unlock()
	}()

	defer func() {
		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}()

	if nic.vnetHdr {
		var err error
		nic.toWrite, err = nic.handleGRO(packets, nic.toWrite[:0])
		if err != nil {
			return err
		}
	} else {
		nic.toWrite = nic.toWrite[:0]
		for pktIndex := range packets {
			nic.toWrite = append(nic.toWrite, pktIndex)
		}
	}

	for _, pktIndex := range nic.toWrite {
		pkt := packets[pktIndex]
		buf := pkt.Bytes()

	ATTEMPT_WRITE:
		if err := nic.tunFile.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return err
		}

		_, err := nic.tunFile.Write(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					goto ATTEMPT_WRITE
				}
			} else if errors.Is(err, syscall.EBADFD) {
				return os.ErrClosed
			}

			return err
		}
	}

	return nil
}

func (nic *Interface) MTU() (int, error) {
	if nic.unmanaged {
		return nic.initalMTU, nil
	}

	link, err := netlink.LinkByName(nic.name)
	if err != nil {
		return 0, fmt.Errorf("failed to find link: %w", err)
	}

	return link.Attrs().MTU, nil
}

func (nic *Interface) BatchSize() int {
	return nic.batchSize
}
