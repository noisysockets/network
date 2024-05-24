// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util_test

import (
	"testing"

	"github.com/noisysockets/network/internal/util"
	"github.com/stretchr/testify/require"
)

func TestConfigWithDefaults(t *testing.T) {
	type config struct {
		A string
		B []int
		C *bool
	}

	defaults := config{
		A: "default",
		B: []int{1, 2, 3},
		C: util.PointerTo(true),
	}

	t.Run("Nil", func(t *testing.T) {
		conf, err := util.ConfigWithDefaults(nil, &defaults)
		require.NoError(t, err)

		require.Equal(t, defaults.A, conf.A)
		require.Equal(t, defaults.B, conf.B)
		require.Equal(t, *defaults.C, *conf.C)
	})

	t.Run("Empty", func(t *testing.T) {
		conf, err := util.ConfigWithDefaults(&config{}, &defaults)
		require.NoError(t, err)

		require.Equal(t, defaults.A, conf.A)
		require.Equal(t, defaults.B, conf.B)
		require.Equal(t, *defaults.C, *conf.C)
	})

	t.Run("Partial", func(t *testing.T) {
		conf, err := util.ConfigWithDefaults(&config{A: "partial", C: util.PointerTo(false)}, &defaults)
		require.NoError(t, err)

		require.Equal(t, "partial", conf.A)
		require.Equal(t, defaults.B, conf.B)
		require.False(t, *conf.C)
	})
}
