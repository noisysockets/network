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
	"testing"

	"github.com/noisysockets/network"
	"github.com/stretchr/testify/require"
)

func TestHostNetwork(t *testing.T) {
	net := network.Host()

	t.Run("Domain", func(t *testing.T) {
		domain, err := net.Domain()
		require.NoError(t, err)

		require.NotEmpty(t, domain)
	})
}
