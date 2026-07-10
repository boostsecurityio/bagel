// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultProbes pins the built-in probe set. A newly added probe that isn't
// wired into DefaultProbes fails this test.
func TestDefaultProbes(t *testing.T) {
	t.Parallel()

	want := []string{
		"git",
		"env",
		"npm",
		"ssh",
		"shell_history",
		"cloud",
		"jetbrains",
		"gh",
		"ai_credentials",
		"ai_chats",
		"wireguard",
		"pypi",
		"kube",
		"docker",
		"iac",
		"ai_mcp",
		"ai_context",
	}

	probes := DefaultProbes(&models.Config{}, detector.NewDefaultRegistry())
	require.Len(t, probes, len(want), "default probe count changed")

	got := make([]string, len(probes))
	for i, p := range probes {
		got[i] = p.Name()
	}
	assert.Equal(t, want, got, "default probe set/order changed")
}

// TestDefaultProbes_EnabledReflectsConfig confirms each probe's enabled flag is
// wired from cfg (callers filter on IsEnabled).
func TestDefaultProbes_EnabledReflectsConfig(t *testing.T) {
	t.Parallel()

	cfg := &models.Config{}
	cfg.Probes.Git.Enabled = true
	// everything else stays false

	for _, p := range DefaultProbes(cfg, detector.NewDefaultRegistry()) {
		if p.Name() == "git" {
			assert.True(t, p.IsEnabled(), "git should be enabled")
		} else {
			assert.False(t, p.IsEnabled(), "%s should be disabled", p.Name())
		}
	}
}
