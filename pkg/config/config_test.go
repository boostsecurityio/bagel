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

// TestLoad_NoConfigFileUsesDefaults verifies that when auto-discovery finds no
// config file, Load succeeds with built-in defaults — every probe enabled and
// the file-index patterns populated.
func TestLoad_NoConfigFileUsesDefaults(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // empty home, no bagel.yaml
	t.Chdir(t.TempDir())          // empty cwd, no bagel.yaml on "." path

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.Probes.Git.Enabled)
	assert.True(t, cfg.Probes.Cloud.Enabled)
	assert.NotEmpty(t, cfg.FileIndex.Patterns)
}

// TestLoad_DiscoveredConfigUnusableFallsBack verifies that when auto-discovery
// cannot turn up a usable config file, Load does not abort the scan: it falls
// back to defaults instead of erroring.
func TestLoad_DiscoveredConfigUnusableFallsBack(t *testing.T) {
	dir := t.TempDir()
	// A directory named bagel.yaml means there's no readable config file to
	// load, standing in for an absent/inaccessible config under auto-discovery.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bagel.yaml"), 0o755))
	t.Chdir(dir)

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, cfg.Probes.Git.Enabled)
}

// TestLoad_ExplicitConfigFailsLoudly verifies the opposite contract: when the
// user explicitly names a --config file that cannot be read, Load returns an
// error rather than silently using defaults.
func TestLoad_ExplicitConfigFailsLoudly(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := Load(missing)
	require.Error(t, err)
}
