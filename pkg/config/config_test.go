// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_LegacyAICliMirroredOntoNewProbes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bagel.yaml")
	contents := `version: 1
probes:
  ai_cli:
    enabled: false
    flags:
      max_file_size: 2048
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Both new probes should inherit the legacy block verbatim.
	assert.False(t, cfg.Probes.AICredentials.Enabled)
	assert.False(t, cfg.Probes.AIChats.Enabled)
	assert.Equal(t, 2048, cfg.Probes.AICredentials.Flags["max_file_size"])
	assert.Equal(t, 2048, cfg.Probes.AIChats.Flags["max_file_size"])
}

func TestLoad_NewAIProbeKeysHonoredWhenNoLegacy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bagel.yaml")
	contents := `version: 1
probes:
  ai_credentials:
    enabled: false
  ai_chats:
    enabled: true
`
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.False(t, cfg.Probes.AICredentials.Enabled)
	assert.True(t, cfg.Probes.AIChats.Enabled)
}

func TestLoad_DefaultsEnableBothAIProbes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bagel.yaml")
	require.NoError(t, os.WriteFile(path, []byte("version: 1\n"), 0600))

	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.Probes.AICredentials.Enabled)
	assert.True(t, cfg.Probes.AIChats.Enabled)
}
