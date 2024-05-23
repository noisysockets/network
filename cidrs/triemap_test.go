// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Portions of this file are based on code originally from the kubernetes project.
 *
 * Copyright 2022 The Kubernetes Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cidrs_test

import (
	"net/netip"
	"testing"

	"github.com/noisysockets/network/cidrs"
)

var testCIDRS = map[string][]netip.Prefix{
	"eu-west-3": {
		netip.MustParsePrefix("35.180.0.0/16"),
		netip.MustParsePrefix("52.93.127.17/32"),
		netip.MustParsePrefix("52.93.127.172/31"),
	},
	"us-east-1": {
		netip.MustParsePrefix("52.93.127.173/32"),
	},
	"us-west-2": {
		netip.MustParsePrefix("2600:1f01:4874::/47"),
		netip.MustParsePrefix("52.94.76.0/22"),
	},
	"ap-northeast-1": {
		netip.MustParsePrefix("52.93.127.174/32"),
		netip.MustParsePrefix("52.93.127.175/32"),
		netip.MustParsePrefix("52.93.127.176/32"),
		netip.MustParsePrefix("52.93.127.177/32"),
		netip.MustParsePrefix("52.93.127.178/32"),
		netip.MustParsePrefix("52.93.127.179/32"),
	},
	"ap-southeast-3": {
		netip.MustParsePrefix("2400:6500:0:9::2/128"),
	},
}

var testCases = []struct {
	Addr           netip.Addr
	ExpectedRegion string
}{
	{Addr: netip.MustParseAddr("35.180.1.1"), ExpectedRegion: "eu-west-3"},
	{Addr: netip.MustParseAddr("35.250.1.1"), ExpectedRegion: ""},
	{Addr: netip.MustParseAddr("35.0.1.1"), ExpectedRegion: ""},
	{Addr: netip.MustParseAddr("52.94.76.1"), ExpectedRegion: "us-west-2"},
	{Addr: netip.MustParseAddr("52.94.77.1"), ExpectedRegion: "us-west-2"},
	{Addr: netip.MustParseAddr("52.93.127.172"), ExpectedRegion: "eu-west-3"},
	// ipv6
	{Addr: netip.MustParseAddr("2400:6500:0:9::2"), ExpectedRegion: "ap-southeast-3"},
	{Addr: netip.MustParseAddr("2400:6500:0:9::1"), ExpectedRegion: ""},
	{Addr: netip.MustParseAddr("2400:6500:0:9::3"), ExpectedRegion: ""},
	{Addr: netip.MustParseAddr("2600:1f01:4874::47"), ExpectedRegion: "us-west-2"},
}

func TestTrieMap(t *testing.T) {
	trieMap := cidrs.NewTrieMap[string]()
	for value, cidrs := range testCIDRS {
		for _, cidr := range cidrs {
			trieMap.Insert(cidr, value)
		}
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.Addr.String(), func(t *testing.T) {
			t.Parallel()
			// NOTE: we set region == "" for no-contains
			expectedContains := tc.ExpectedRegion != ""
			ip := tc.Addr
			region, contains := trieMap.Get(ip)
			if contains != expectedContains || region != tc.ExpectedRegion {
				t.Fatalf(
					"result does not match for %v, got: (%q, %t) expected: (%q, %t)",
					ip, region, contains, tc.ExpectedRegion, expectedContains,
				)
			}
		})
	}
}

func TestTrieMapEmpty(t *testing.T) {
	trieMap := cidrs.NewTrieMap[string]()
	v, contains := trieMap.Get(netip.MustParseAddr("127.0.0.1"))
	if contains || v != "" {
		t.Fatalf("empty TrieMap should not contain anything")
	}
	v, contains = trieMap.Get(netip.MustParseAddr("::1"))
	if contains || v != "" {
		t.Fatalf("empty TrieMap should not contain anything")
	}
}

func TestTrieMapSlashZero(t *testing.T) {
	// test the ??? case that we insert into the root with a /0
	trieMap := cidrs.NewTrieMap[string]()
	trieMap.Insert(netip.MustParsePrefix("0.0.0.0/0"), "all-ipv4")
	trieMap.Insert(netip.MustParsePrefix("::/0"), "all-ipv6")
	v, contains := trieMap.Get(netip.MustParseAddr("127.0.0.1"))
	if !contains || v != "all-ipv4" {
		t.Fatalf("TrieMap failed to match IPv4 with all IPs in one /0")
	}
	v, contains = trieMap.Get(netip.MustParseAddr("::1"))
	if !contains || v != "all-ipv6" {
		t.Fatalf("TrieMap failed to match IPv6 with all IPs in one /0")
	}
}
