// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStableHostname(t *testing.T) {
	t.Parallel()

	t.Run("returns a non-empty hostname", func(t *testing.T) {
		t.Parallel()
		hostname, err := GetStableHostname()
		require.NoError(t, err)
		assert.NotEmpty(t, hostname)
	})
}
