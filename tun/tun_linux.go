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
	"unsafe"

	"github.com/noisysockets/netutil/defaults"
	"github.com/noisysockets/netutil/ptr"
	"github.com/noisysockets/network"
	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

var _ network.Interface = (*NativeTun)(nil)

// NativeTun is a TUN device implementation for linux.
type NativeTun struct {
	logger *slog.Logger

	tunFile *os.File

	closeOnce sync.Once

	name string // name of interface

	readOpMu  sync.Mutex
	writeOpMu sync.Mutex

	packetPool *network.PacketPool
}

// Create creates a new TUN device with the specified configuration.
func Create(ctx context.Context, logger *slog.Logger, conf Configuration) (network.Interface, error) {
	confWithDefaults, err := defaults.WithDefaults(&conf, &Configuration{
		MTU:        ptr.To(DefaultMTU),
		PacketPool: network.NewPacketPool(0, false),
	})
	if err != nil {
		return nil, err
	}
	conf = *confWithDefaults

	if conf.Name == "" {
		return nil, errors.New("TUN device name must be specified")
	}

	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("TUN/TAP device not found (missing CONFIG_TUN)")
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(conf.Name)
	if err != nil {
		return nil, err
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.
	file := os.NewFile(uintptr(nfd), cloneDevicePath)

	tun := &NativeTun{
		logger:     logger,
		tunFile:    file,
		packetPool: conf.PacketPool,
	}

	tun.name, err = tun.nameSlow()
	if err != nil {
		_ = tun.Close()
		return nil, err
	}

	if err := tun.setMTU(*conf.MTU); err != nil {
		_ = tun.Close()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) Close() error {
	var err error
	tun.closeOnce.Do(func() {
		err = tun.tunFile.Close()
	})
	return err
}

func (tun *NativeTun) Read(ctx context.Context, packets []*network.Packet, offset int) ([]*network.Packet, error) {
	tun.readOpMu.Lock()
	defer tun.readOpMu.Unlock()

	if len(packets) > 0 {
		packets = packets[:0]
	}

	pkt := tun.packetPool.Borrow()
	pkt.Offset = offset

	for {
		err := tun.tunFile.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			return packets, err
		}

		pkt.Size, err = tun.tunFile.Read(pkt.Buf[offset:])
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
		packets = append(packets, pkt)
		return packets, nil
	}
}

func (tun *NativeTun) Write(ctx context.Context, packets []*network.Packet) (int, error) {
	tun.writeOpMu.Lock()
	defer tun.writeOpMu.Unlock()

	defer func() {
		for i, pkt := range packets {
			pkt.Release()
			packets[i] = nil
		}
	}()

	var total int
	for _, pkt := range packets {
		buf := pkt.Bytes()

	ATTEMPT_WRITE:
		if err := tun.tunFile.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return total, err
		}

		n, err := tun.tunFile.Write(buf)
		total += n

		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				select {
				case <-ctx.Done():
					return total, ctx.Err()
				default:
					buf = buf[n:]
					if len(buf) > 0 {
						goto ATTEMPT_WRITE
					} else {
						continue
					}
				}
			} else if errors.Is(err, syscall.EBADFD) {
				return total, os.ErrClosed
			}

			return total, err
		}
	}

	return total, nil
}

func (tun *NativeTun) MTU() int {
	name := tun.Name()

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		tun.logger.Warn("Failed to open datagram socket",
			slog.Any("error", err))
		return DefaultMTU
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		tun.logger.Warn("Failed to get MTU of TUN device",
			slog.Any("error", errno))
		return DefaultMTU
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])))
}

func (tun *NativeTun) Name() string {
	return tun.name
}

func (tun *NativeTun) BatchSize() int {
	return 1
}

func (tun *NativeTun) setMTU(n int) error {
	name := tun.Name()

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	// do ioctl call
	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set MTU of TUN device: %w", errno)
	}

	return nil
}

func (tun *NativeTun) nameSlow() (string, error) {
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}
