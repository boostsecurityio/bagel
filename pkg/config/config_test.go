// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

// TestLoad_ExtensionlessBinaryNotMatched guards the regression where running
// `./bagel scan` from the binary's own directory crashed with
// "yaml: control characters are not allowed": with a config type set, viper
// matches the extensionless `bagel` binary as a config file and tries to parse
// it. Load must not even attempt to parse it.
//
// This asserts on the log output, not just the absence of an error: the
// resilience switch in Load would swallow the parse failure and let the test
// pass regardless. The only thing that proves the binary was never parsed is
// that no "parsing config" failure was logged — which fails if SetConfigType
// is restored.
func TestLoad_ExtensionlessBinaryNotMatched(t *testing.T) {
	logs := captureGlobalLog(t)

	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bagel"),
		[]byte("\x7fELF\x02\x01\x01\x00\x00\x00"), 0o755)) // binary with control chars
	t.Chdir(dir)

	cfg, err := Load("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.True(t, cfg.Probes.Git.Enabled)
	assert.NotEmpty(t, cfg.FileIndex.Patterns)

	// The binary must never be fed to the YAML parser.
	assert.NotContains(t, logs.String(), "parsing config",
		"the bagel binary was matched and parsed as a config file; "+
			"is SetConfigType set during auto-discovery?")
}

// captureGlobalLog redirects the package-global zerolog logger into a buffer
// for the duration of the test and restores it afterward.
func captureGlobalLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Logger
	log.Logger = zerolog.New(buf)
	t.Cleanup(func() { log.Logger = prev })
	return buf
}
