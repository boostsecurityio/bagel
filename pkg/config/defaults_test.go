// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultPatterns_MatchesLoadedConfig verifies DefaultPatterns is the single
// source of truth: the patterns a default Load produces must match it exactly,
// by name and order.
func TestDefaultPatterns_MatchesLoadedConfig(t *testing.T) {
	t.Parallel()

	defaults := DefaultPatterns()
	require.NotEmpty(t, defaults)

	cfg, err := Load("")
	require.NoError(t, err)
	require.Len(t, cfg.FileIndex.Patterns, len(defaults),
		"loaded pattern count must match DefaultPatterns")

	for i, p := range defaults {
		loaded := cfg.FileIndex.Patterns[i]
		assert.Equal(t, p.Name, loaded.Name, "pattern name mismatch at index %d", i)
		assert.Equal(t, p.Type, loaded.Type, "pattern type mismatch for %q", p.Name)
		assert.Equal(t, p.Patterns, loaded.Patterns, "globs mismatch for %q", p.Name)
	}
}
