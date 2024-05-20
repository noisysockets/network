// SPDX-License-Identifier: MIT

/* Package main provides an example implementation of SLiRP.
 *
 * You will need to run this program with CAP_NET_ADMIN capabilities to create
 * the TUN interface.
 *
 * For example:
 *
 *  $ go build -o slirp
 *  $ sudo setcap cap_net_admin=+ep ./slirp
 *  $ ./slirp
 *
 * For testing you will need to create a network namespace:
 *
 *  $ sudo mkdir -p /etc/netns/slirp-ns
 *  $ echo "nameserver 1.1.1.1" | sudo tee /etc/netns/slirp-ns/resolv.conf
 *  $ sudo ip netns add slirp-ns
 *  $ sudo ip link set nsh0 netns slirp-ns
 *  $ sudo ip netns exec slirp-ns ip addr add 172.21.248.2/24 dev nsh0
 *  $ sudo ip netns exec slirp-ns ip link set nsh0 up
 *  $ sudo ip netns exec slirp-ns ip route add default via 172.21.248.1 dev nsh0
 *
 * You can then open a shell in the network namespace, any traffic will be
 * forwarded through the SLiRP example:
 *
 *  $ sudo ip netns exec slirp-ns bash
 *  $ curl http://icanhazip.com
 *
 * To clean up when you are done, you can delete the network namespace:
 *
 *	$ sudo ip netns delete slirp-ns
 */
package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/noisysockets/network"
	"github.com/noisysockets/network/forwarder"
	"github.com/noisysockets/network/tun"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	logger.Info("Creating TUN interface", slog.String("name", "nsh0"))

	ctx := context.Background()
	nic, err := tun.CreateTUN(ctx, logger, "nsh0", tun.DefaultMTU)
	if err != nil {
		logger.Error("Failed to create TUN interface", slog.Any("error", err))
		os.Exit(1)
	}
	defer nic.Close()

	logger.Info("Initializing userspace network stack")

	fwd := forwarder.New(ctx, logger, network.Host(), nil)

	net, err := network.Userspace(ctx, logger, nic, &network.UserspaceNetworkConfig{
		Addresses: []netip.Prefix{
			netip.MustParsePrefix("172.21.248.1/32"),
		},
		EnableSpoofing:        true,
		EnablePromiscuousMode: true,
		TCPProtocolHandler:    fwd.TCPProtocolHandler,
		UDPProtocolHandler:    fwd.UDPProtocolHandler,
	})
	if err != nil {
		_ = nic.Close()
		logger.Error("Failed to create userspace network", slog.Any("error", err))
		os.Exit(1)
	}
	defer net.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	<-sig
}
