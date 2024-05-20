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
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"time"
)

var protoSplitter = regexp.MustCompile(`^(tcp|udp)(4|6)?$`)

// TODO: no need for regex here, there's only 4 possible values.
func parseNetwork(network string) (proto string, useIPV4, useIPV6 bool, err error) {
	useIPV4, useIPV6 = true, true
	matches := protoSplitter.FindStringSubmatch(network)
	if matches != nil {
		if len(matches) < 2 {
			return "", false, false, fmt.Errorf("invalid network %q", network)
		}

		proto = matches[1]

		if len(matches[2]) != 0 {
			useIPV4 = matches[2][0] == '4'
			useIPV6 = !useIPV4
		}
	}

	return
}

func parseAndFilterAddrs(addrs []string, useIPV4, useIPV6 bool) []netip.Addr {
	var filtered []netip.Addr
	for _, addrStr := range addrs {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}

		if (useIPV4 && addr.Is4()) || (useIPV6 && addr.Is6()) {
			filtered = append(filtered, addr)
		}
	}
	return filtered
}

func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}

	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, os.ErrDeadlineExceeded
	}

	timeout := timeRemaining / time.Duration(addrsRemaining)
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}

	return now.Add(timeout), nil
}
