// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package wsl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkipDistro(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		skip bool
	}{
		{"Ubuntu", false},
		{"Ubuntu-22.04", false},
		{"kali-linux", false},
		{"docker-desktop", true},
		{"docker-desktop-data", true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.skip, skipDistro(tt.name), tt.name)
	}
}

func TestUNCCandidates(t *testing.T) {
	t.Parallel()
	got := uncCandidates("Ubuntu")
	assert.Equal(t, []string{`\\wsl.localhost\Ubuntu`, `\\wsl$\Ubuntu`}, got,
		"modern \\\\wsl.localhost form must be probed before the legacy \\\\wsl$ form")
}
