// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvProbe_ProcessShellConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test shell config file
	configPath := filepath.Join(tmpDir, ".bashrc")
	configContent := `# Shell configuration
export PATH=/usr/local/bin:$PATH
export DB_PASSWORD=secret123
export API_TOKEN=token456
alias ll='ls -la'

# GitHub PAT for testing
export GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Create detector registry with GitHub PAT detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewGenericAPIKeyDetector())

	// Create probe
	probe := NewEnvProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file
	findings := probe.processShellConfigFile(ctx, configPath)

	// Should find:
	// 1. GitHub PAT detected by detector
	// 2. Potentially generic API key detections for the other values
	assert.GreaterOrEqual(t, len(findings), 1, "Should detect at least the GitHub PAT")

	// Check finding types
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
		t.Logf("Finding ID: %s, Title: %s", f.ID, f.Title)
	}

	// GitHub PAT should be detected with ID "github-token-classic-pat"
	assert.True(t, findingIDs["github-token-classic-pat"], "Should detect GitHub PAT")
}

func TestEnvProbe_ProcessEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test .env file with world-readable permissions
	envPath := filepath.Join(tmpDir, ".env")
	envContent := `NODE_ENV=production
DB_HOST=localhost
DB_PASSWORD=secret123
API_TOKEN=token456

# NPM token
NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890`

	err := os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)

	// Create detector registry with NPM token detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewEnvProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file
	findings := probe.processEnvFile(ctx, envPath)

	// Should find:
	// 1. NPM token detected by detector
	assert.GreaterOrEqual(t, len(findings), 1, "Should detect NPM token")

	// Check finding types
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
	}

	assert.True(t, findingIDs["npm-token-npm-auth-token"], "Should detect NPM token")
}

func TestEnvProbe_Execute_WithFileIndex(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test .bashrc file
	bashrcPath := filepath.Join(tmpDir, ".bashrc")
	bashrcContent := `export PATH=/usr/bin
export API_TOKEN=token123`
	err := os.WriteFile(bashrcPath, []byte(bashrcContent), 0644)
	require.NoError(t, err)

	// Create test .zshrc file
	zshrcPath := filepath.Join(tmpDir, ".zshrc")
	zshrcContent := `export PATH=/usr/local/bin
export DB_PASSWORD=secret456`
	err = os.WriteFile(zshrcPath, []byte(zshrcContent), 0644)
	require.NoError(t, err)

	// Create test .env file
	envPath := filepath.Join(tmpDir, ".env")
	envContent := `API_KEY=key789
DB_SECRET=hidden`
	err = os.WriteFile(envPath, []byte(envContent), 0644)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("bashrc", bashrcPath)
	index.Add("zshrc", zshrcPath)
	index.Add("env_files", envPath)

	// Create detector registry with generic API key detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewGenericAPIKeyDetector())

	// Create probe
	probe := NewEnvProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)

	// May or may not find secrets depending on entropy
	// The generic API key detector will check for high-entropy values
	// At minimum, should not error and should scan the files
	t.Logf("Found %d findings", len(findings))
}

func TestEnvProbe_Execute_WithoutFileIndex(t *testing.T) {
	ctx := context.Background()

	// Create detector registry with GitHub PAT detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	// Create probe without file index
	probe := NewEnvProbe(models.ProbeSettings{Enabled: true}, registry)

	// Set a test env var with a GitHub PAT
	t.Setenv("TEST_GITHUB_TOKEN", "ghp_1234567890123456789012345678901234567890")

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)

	// Should still scan environment variables
	// Should detect the GitHub PAT
	var foundGitHubPAT bool
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			foundGitHubPAT = true
			break
		}
	}

	assert.True(t, foundGitHubPAT, "Should detect GitHub PAT in environment variable")
}

func TestEnvProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewEnvProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "env", probe.Name())
}

func TestEnvProbe_IsEnabled(t *testing.T) {
	registry := detector.NewRegistry()

	tests := []struct {
		name    string
		enabled bool
	}{
		{
			name:    "Probe enabled",
			enabled: true,
		},
		{
			name:    "Probe disabled",
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := NewEnvProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}
