// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package matcher

import "github.com/noisysockets/netstack/pkg/tcpip/stack"

var _ stack.Matcher = (*notMatcher)(nil)

type notMatcher struct {
	inner stack.Matcher
}

// Not creates a new matcher that inverts the result of another matcher.
func Not(inner stack.Matcher) *notMatcher {
	return &notMatcher{inner: inner}
}

func (m *notMatcher) Match(hook stack.Hook, pkt *stack.PacketBuffer, inputInterfaceName, outputInterfaceName string) (matches bool, hotdrop bool) {
	matches, hotdrop = m.inner.Match(hook, pkt, inputInterfaceName, outputInterfaceName)
	return !matches, hotdrop
}
