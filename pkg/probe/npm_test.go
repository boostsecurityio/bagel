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

func TestParseNPMConfig(t *testing.T) {
	content := `registry=https://registry.npmjs.org/
strict-ssl=false
always-auth=true
//registry.npmjs.org/:_authToken=npm_token1234567890123456789012345678901`

	config := parseNPMConfig(content)

	assert.Equal(t, "https://registry.npmjs.org/", config["registry"])
	assert.Equal(t, "false", config["strict-ssl"])
	assert.Equal(t, "true", config["always-auth"])
}

func TestParseNPMConfigYAML(t *testing.T) {
	content := `npmRegistries:
  "https://registry.yarnpkg.com":
    npmAuthToken: "npm_token1234567890123456789012345678901"
strictSsl: false`

	config := parseNPMConfig(content)

	// Check both colon-based and quoted values
	assert.Contains(t, config, "strictSsl")
	assert.Equal(t, "false", config["strictSsl"])
}

func TestParseNPMConfigComments(t *testing.T) {
	content := `# This is a comment
registry=https://registry.npmjs.org/
; This is also a comment
strict-ssl=true`

	config := parseNPMConfig(content)

	assert.Equal(t, "https://registry.npmjs.org/", config["registry"])
	assert.Equal(t, "true", config["strict-ssl"])
	assert.Len(t, config, 2) // Should not include comments
}

func TestCheckStrictSSL(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &NPMProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "SSL verify disabled",
			config:    map[string]string{"strict-ssl": "false"},
			wantCount: 1,
		},
		{
			name:      "SSL verify enabled",
			config:    map[string]string{"strict-ssl": "true"},
			wantCount: 0,
		},
		{
			name:      "SSL verify not set",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name:      "SSL verify disabled case insensitive",
			config:    map[string]string{"strict-ssl": "FALSE"},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkStrictSSL("test.npmrc", tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "npm-ssl-verify-disabled", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckInsecureRegistry(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &NPMProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "HTTP registry",
			config:    map[string]string{"registry": "http://registry.example.com"},
			wantCount: 1,
		},
		{
			name:      "HTTPS registry (safe)",
			config:    map[string]string{"registry": "https://registry.npmjs.org"},
			wantCount: 0,
		},
		{
			name:      "Scoped HTTP registry",
			config:    map[string]string{"@myorg:registry": "http://registry.example.com"},
			wantCount: 1,
		},
		{
			name:      "No registry configured",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name: "Multiple registries with one insecure",
			config: map[string]string{
				"registry":        "https://registry.npmjs.org",
				"@myorg:registry": "http://registry.example.com",
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkInsecureRegistry("test.npmrc", tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "npm-insecure-registry", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckAlwaysAuth(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &NPMProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "Always auth enabled",
			config:    map[string]string{"always-auth": "true"},
			wantCount: 1,
		},
		{
			name:      "Always auth disabled",
			config:    map[string]string{"always-auth": "false"},
			wantCount: 0,
		},
		{
			name:      "Always auth not set",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name:      "Always auth enabled case insensitive",
			config:    map[string]string{"always-auth": "TRUE"},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkAlwaysAuth("test.npmrc", tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "npm-always-auth-enabled", findings[0].ID)
				assert.Equal(t, "low", findings[0].Severity)
			}
		})
	}
}

func TestNPMProbe_Execute(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test .npmrc file
	npmrcPath := filepath.Join(tmpDir, ".npmrc")
	npmrcContent := `registry=https://registry.npmjs.org/
strict-ssl=false
//registry.npmjs.org/:_authToken=npm_token1234567890123456789012345678901`
	err := os.WriteFile(npmrcPath, []byte(npmrcContent), 0600)
	require.NoError(t, err)

	// Create test .yarnrc file
	yarnrcPath := filepath.Join(tmpDir, ".yarnrc")
	yarnrcContent := `registry "https://registry.yarnpkg.com"
npmAuthToken "npm_yarntoken234567890123456789012345678"`
	err = os.WriteFile(yarnrcPath, []byte(yarnrcContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("npmrc", npmrcPath)
	index.Add("yarnrc", yarnrcPath)

	// Create detector registry with NPM token detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create NPM probe
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Should find at least:
	// 1. strict-ssl disabled in .npmrc
	// 2. NPM token in .npmrc
	// 3. NPM token in .yarnrc
	assert.GreaterOrEqual(t, len(findings), 3)

	// Check for SSL finding
	hasSSLFinding := false
	for _, f := range findings {
		if f.ID == "npm-ssl-verify-disabled" {
			hasSSLFinding = true
			assert.Equal(t, "high", f.Severity)
		}
	}
	assert.True(t, hasSSLFinding, "Should detect SSL verification disabled")

	// Check for token findings (both tokens should be detected as npm-auth-token)
	tokenCount := 0
	for _, f := range findings {
		if f.ID == "npm-token-npm-auth-token" {
			tokenCount++
			assert.Equal(t, "critical", f.Severity)
		}
	}
	assert.GreaterOrEqual(t, tokenCount, 2, "Should detect at least 2 tokens")
}

func TestNPMProbe_ExecuteWithoutFileIndex(t *testing.T) {
	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create NPM probe without setting file index
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestNPMProbe_ProcessConfigFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test config file with multiple issues
	configPath := filepath.Join(tmpDir, "test.npmrc")
	configContent := `registry=http://insecure-registry.example.com
strict-ssl=false
always-auth=true
//registry.npmjs.org/:_authToken=npm_token1234567890123456789012345678901`
	err := os.WriteFile(configPath, []byte(configContent), 0600)
	require.NoError(t, err)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create NPM probe
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process config file
	ctx := context.Background()
	findings := probe.processConfigFile(ctx, configPath)

	// Should find:
	// 1. Insecure HTTP registry
	// 2. SSL verification disabled
	// 3. Always-auth enabled (informational)
	// 4. NPM token
	assert.GreaterOrEqual(t, len(findings), 4)

	// Check finding types
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
	}

	assert.True(t, findingIDs["npm-insecure-registry"])
	assert.True(t, findingIDs["npm-ssl-verify-disabled"])
	assert.True(t, findingIDs["npm-always-auth-enabled"])
	assert.True(t, findingIDs["npm-token-npm-auth-token"])
}

func TestNPMProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "npm", probe.Name())
}

func TestNPMProbe_IsEnabled(t *testing.T) {
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
			probe := NewNPMProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestNPMProbe_EdgeCases(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create empty config file
	emptyPath := filepath.Join(tmpDir, "empty.npmrc")
	err := os.WriteFile(emptyPath, []byte(""), 0600)
	require.NoError(t, err)

	// Create config file with only comments
	commentsPath := filepath.Join(tmpDir, "comments.npmrc")
	commentsContent := `# This is a comment
; Another comment
# registry=https://example.com`
	err = os.WriteFile(commentsPath, []byte(commentsContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("npmrc", emptyPath)
	index.Add("npmrc", commentsPath)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create NPM probe
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	// Should return no findings for empty/comment-only files
	assert.Empty(t, findings)
}

func TestNPMProbe_FileReadError(t *testing.T) {
	// Build file index with non-existent file
	index := fileindex.NewFileIndex()
	index.Add("npmrc", "/path/to/nonexistent/file.npmrc")

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewNPMTokenDetector())

	// Create NPM probe
	probe := NewNPMProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe - should not error, just skip unreadable files
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings)
}
