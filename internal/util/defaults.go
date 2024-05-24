// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 The Noisy Sockets Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package util

import (
	"dario.cat/mergo"
	"github.com/jinzhu/copier"
)

// ConfigWithDefaults populates the provided configuration with its the default values.
func ConfigWithDefaults[T any](conf, defaults *T) (*T, error) {
	var confWithDefaults T
	if conf != nil {
		if err := copier.Copy(&confWithDefaults, conf); err != nil {
			return nil, err
		}
	}

	if err := mergo.Merge(&confWithDefaults, defaults, mergo.WithoutDereference); err != nil {
		return nil, err
	}

	return &confWithDefaults, nil
}
