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
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/noisysockets/network/internal/addrselect"
	"github.com/noisysockets/network/internal/util"
)

const (
	dnsDefaultPort = 53
)

// Resolver looks up names and numbers (it's a very minimal reimplementation
// of net.Resolver, with the OS specific parts removed).
type Resolver struct {
	// Servers is the list of DNS servers to query.
	Servers []netip.AddrPort
	// Rotate specifies whether to rotate the list of DNS servers for
	// load balancing (eg. round-robin).
	Rotate bool
	// Timeout is the maximum duration to wait for a query to complete
	// (including retries).
	Timeout time.Duration
	// DialContext is used to establish a connection to a DNS server.
	DialContext func(ctx context.Context, network, address string) (stdnet.Conn, error)
}

// LookupHost looks up the IP addresses for the given host.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// Is it an IP address?
	if _, err := netip.ParseAddr(host); err == nil {
		return []string{host}, nil
	}

	return r.lookupDomainName(ctx, host)
}

func (r *Resolver) lookupDomainName(ctx context.Context, name string) ([]string, error) {
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, &stdnet.DNSError{
			Err:        ErrNoSuchHost.Error(),
			Name:       name,
			IsNotFound: true,
		}
	}

	client := &dns.Client{
		Net:     "udp",
		Timeout: r.Timeout,
	}

	rotatedServers := make([]netip.AddrPort, len(r.Servers))
	copy(rotatedServers, r.Servers)

	// Rotate the nameserver list for load balancing.
	if r.Rotate {
		rotatedServers = util.Shuffle(rotatedServers)
	}

	var firstErr error
	var addrs []netip.Addr

	for _, server := range rotatedServers {
		for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA} {
			in, err := r.queryServer(ctx, client, server, queryType, name)
			if err != nil {
				if firstErr == nil {
					firstErr = &stdnet.DNSError{Err: err.Error(), Name: name, Server: server.String()}
				}
				continue
			}

			for _, rr := range in.Answer {
				switch rr := rr.(type) {
				case *dns.A:
					addrs = append(addrs, netip.AddrFrom4([4]byte(rr.A.To4())))
				case *dns.AAAA:
					addrs = append(addrs, netip.AddrFrom16([16]byte(rr.AAAA.To16())))
				}
			}
		}

		if len(addrs) > 0 {
			dial := func(network, address string) (stdnet.Conn, error) {
				return r.DialContext(ctx, network, address)
			}
			addrselect.SortByRFC6724(dial, addrs)
			return util.ToStrings(addrs), nil
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}

	return nil, &stdnet.DNSError{
		Err:        ErrNoSuchHost.Error(),
		Name:       name,
		IsNotFound: true,
	}
}

func (r *Resolver) queryServer(ctx context.Context, client *dns.Client, server netip.AddrPort, queryType uint16, host string) (*dns.Msg, error) {
	dnsErr := &stdnet.DNSError{
		Server: server.String(),
		Name:   host,
	}

	if client.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.Timeout)
		defer cancel()
	}

	if server.Port() == 0 {
		server = netip.AddrPortFrom(server.Addr(), dnsDefaultPort)
	}

	conn, err := r.DialContext(ctx, client.Net, server.String())
	if err != nil {
		dnsErr.Err = err.Error()
		dnsErr.IsTimeout = errors.Is(err, context.DeadlineExceeded)
		return nil, dnsErr
	}
	defer conn.Close()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(host), queryType)

	reply, _, err := client.ExchangeWithConn(req, &dns.Conn{Conn: conn})
	if err != nil {
		dnsErr.Err = err.Error()
		dnsErr.IsTimeout = errors.Is(err, context.DeadlineExceeded)
		return nil, dnsErr
	}

	return reply, nil
}
