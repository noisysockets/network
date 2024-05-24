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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/neilotoole/slogt"
	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
)

func TestUserspaceNetwork(t *testing.T) {
	ctx := context.Background()

	logger := slogt.New(t)

	nicA, nicB := network.Pipe(1500, 16)
	t.Cleanup(func() {
		_ = nicA.Close()
		_ = nicB.Close()
	})

	netA, err := network.Userspace(ctx, logger.With(slog.String("net", "a")), nicA, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netA.Close()
	})

	netB, err := network.Userspace(ctx, logger.With(slog.String("net", "b")), nicB, network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netB.Close()
	})

	// Test connectivity, run a little echo server on netA and dial it from netB.

	// Start echo server.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello: %s", r.RemoteAddr)
	})

	lis, err := netA.Listen("tcp", ":0")
	require.NoError(t, err)

	srv := &http.Server{
		Handler: mux,
	}
	t.Cleanup(func() {
		_ = srv.Close()
	})

	go func() {
		_ = srv.Serve(lis)
	}()

	// Dial echo server.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: netB.DialContext,
		},
	}

	resp, err := client.Get(fmt.Sprintf("http://%s/", lis.Addr().String()))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	require.Equal(t, resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.True(t, strings.Contains(string(body), "hello"))
}
