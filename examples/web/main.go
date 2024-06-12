// SPDX-License-Identifier: MIT

/* Package main provides an example of a simple HTTP server that listens on a
 * TUN interface.
 *
 * You will need to run this program with CAP_NET_ADMIN capabilities to create
 * the TUN interface.
 *
 * For example:
 *
 *  $ go build -o web
 *  $ sudo setcap cap_net_admin=+ep ./web
 *  $ ./web
 *
 * Once the example is running, you will need to  configure the TUN interface
 * with an IP address and a route to the destination network.
 *
 * For example:
 *
 *  $ sudo ip addr add fdff:7061:ac89::2/64 dev nsh0
 *	$ sudo ip link set dev nsh0 up
 *
 * You can then access the HTTP server by visiting http://[fdff:7061:ac89::1]
 * in your web browser.
 */
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	stdnet "net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/noisysockets/network"
	"github.com/noisysockets/network/tun"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	packetPool := network.NewPacketPool(0, false)

	logger.Info("Creating TUN interface", slog.String("name", "nsh0"))

	ctx := context.Background()
	nic, err := tun.Create(ctx, logger, "nsh0", &tun.Configuration{
		PacketPool: packetPool,
	})
	if err != nil {
		logger.Error("Failed to create TUN interface", slog.Any("error", err))
		os.Exit(1)
	}
	defer nic.Close()

	logger.Info("Initializing userspace network stack")

	net, err := network.Userspace(ctx, logger, nic, network.UserspaceNetworkConfig{
		Hostname: "demo",
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("100.64.0.1/32"),
			netip.MustParsePrefix("fdff:7061:ac89::1/128"),
		},
		PacketPool:        packetPool,
		PacketWriteOffset: tun.VirtioNetHdrLen,
	})
	if err != nil {
		logger.Error("Failed to create userspace network", slog.Any("error", err))
		os.Exit(1)
	}
	defer net.Close()

	ctx, cancel := context.WithCancel(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig

		cancel()
	}()

	if err := runWebServer(ctx, logger, net); err != nil {
		logger.Error("Failed to run server", slog.Any("error", err))
		os.Exit(1)
	}
}

func runWebServer(ctx context.Context, logger *slog.Logger, net network.Network) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Hello, world!"))
	})

	server := &http.Server{
		BaseContext: func(listener stdnet.Listener) context.Context { return ctx },
		Handler:     mux,
	}

	lis, err := net.Listen("tcp", ":80")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer lis.Close()

	go func() {
		<-ctx.Done()

		logger.Info("Shutting down server")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Failed to shutdown server", slog.Any("error", err))
		}
	}()

	logger.Info("Listening for http requests", slog.Any("address", lis.Addr()))

	if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve: %w", err)
	}

	return nil
}
