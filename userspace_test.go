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
	"github.com/noisysockets/netstack/pkg/tcpip/header"
	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
)

func TestUserspaceNetwork(t *testing.T) {
	ctx := context.Background()

	logger := slogt.New(t)

	nicA, nicB := network.Pipe(nil)
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

// Noisy sockets uses a 1280 byte MTU but wireguard uses 1420 bytes by default.
// So make sure that we can receive packets larger than our MTU without blowing
// up.
func TestJumboPacket(t *testing.T) {
	ctx := context.Background()

	logger := slogt.New(t)

	nicA, nicB := network.Pipe(nil)
	t.Cleanup(func() {
		_ = nicA.Close()
		_ = nicB.Close()
	})

	netA, err := network.Userspace(ctx, logger.With(slog.String("net", "a")), &jumboNic{nicA}, network.UserspaceNetworkConfig{
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

	// Start a UDP server on netB.
	udpListener, err := netB.ListenPacket("udp", ":1234")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, udpListener.Close())
	})

	jumboDatagramSize := 9000 - header.IPv4MinimumSize - header.UDPMinimumSize
	rxBuf := make([]byte, jumboDatagramSize)
	rx := make(chan struct{})

	go func() {
		_, _, err := udpListener.ReadFrom(rxBuf)
		if err != nil {
			logger.Error("failed to read from UDP listener", slog.Any("error", err))
		}

		close(rx)
	}()

	// Send a jumbo packet from netA to netB.
	pc, err := netA.DialContext(ctx, "udp", "100.64.0.2:1234")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pc.Close())
	})

	txBuf := []byte(strings.Repeat("a", jumboDatagramSize))
	_, err = pc.Write(txBuf)
	require.NoError(t, err)

	<-rx

	require.Equal(t, txBuf, rxBuf)
}

type jumboNic struct {
	network.Interface
}

func (j *jumboNic) MTU() int {
	return 9000
}
