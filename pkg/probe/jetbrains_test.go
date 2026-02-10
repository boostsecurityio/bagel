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

func TestJetBrainsProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "jetbrains", probe.Name())
}

func TestJetBrainsProbe_IsEnabled(t *testing.T) {
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
			probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestJetBrainsProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()
	registry := detector.NewRegistry()

	probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: true}, registry)

	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestJetBrainsProbe_ProcessWorkspaceFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test workspace file with secrets
	workspacePath := filepath.Join(tmpDir, ".idea", "workspace.xml")
	workspaceContent := `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="RunManager">
    <configuration name="go build my_project" type="GoApplicationRunConfiguration" factoryName="Go Application" temporary="true" nameIsGenerated="true">
      <module name="my_project"/>
      <working_directory value="$PROJECT_DIR$"/>
      <parameters value="upload --token npm_abcdefghijklmnopqrstuvwxyz1234567890"/>
      <envs>
		<env name="GH_TOKEN" value="ghp_1234567890123456789012345678901234567890"/>
      </envs>
      <kind value="PACKAGE"/>
      <package value="package_name"/>
      <directory value="$PROJECT_DIR$"/>
      <filePath value="$PROJECT_DIR$/main.go"/>
      <method v="2"/>
    </configuration>
  </component>
</project>
`

	err := os.Mkdir(filepath.Join(tmpDir, ".idea"), 0700)
	require.NoError(t, err)

	err = os.WriteFile(workspacePath, []byte(workspaceContent), 0600)
	require.NoError(t, err)

	// Create detector registry with GitHub PAT and NPM token detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process the workspace file
	findings := probe.processWorkspaceFile(ctx, workspacePath)

	// Should find GitHub PAT and NPM token
	assert.GreaterOrEqual(t, len(findings), 2)

	// Verify metadata includes config_name and env_var
	for _, finding := range findings {
		assert.Equal(t, "go build my_project", finding.Metadata["config_name"])
		if finding.ID == "github-token-classic-pat" {
			assert.Equal(t, "GH_TOKEN", finding.Metadata["env_var"])
		}
	}
}

func TestJetBrainsProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test workspace file with secrets
	workspacePath := filepath.Join(tmpDir, ".idea", "workspace.xml")
	workspaceContent := `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="RunManager">
    <configuration name="go build my_project" type="GoApplicationRunConfiguration" factoryName="Go Application" temporary="true" nameIsGenerated="true">
      <module name="my_project"/>
      <working_directory value="$PROJECT_DIR$"/>
      <parameters value="upload --token npm_abcdefghijklmnopqrstuvwxyz1234567890"/>
      <envs>
		<env name="GH_TOKEN" value="ghp_1234567890123456789012345678901234567890"/>
      </envs>
      <kind value="PACKAGE"/>
      <package value="package_name"/>
      <directory value="$PROJECT_DIR$"/>
      <filePath value="$PROJECT_DIR$/main.go"/>
      <method v="2"/>
    </configuration>
  </component>
</project>
`

	err := os.Mkdir(filepath.Join(tmpDir, ".idea"), 0700)
	require.NoError(t, err)

	err = os.WriteFile(workspacePath, []byte(workspaceContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("jetbrains", workspacePath)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	// Should find GitHub PAT and NPM token
	assert.GreaterOrEqual(t, len(findings), 2)

	// Verify metadata includes config_name and env_var
	for _, finding := range findings {
		assert.Equal(t, "go build my_project", finding.Metadata["config_name"])
		if finding.ID == "github-token-classic-pat" {
			assert.Equal(t, "GH_TOKEN", finding.Metadata["env_var"])
		}
	}
}
func TestJetBrainsProbe_MultipleConfigurations(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test workspace file with secrets
	workspacePath := filepath.Join(tmpDir, ".idea", "workspace.xml")
	workspaceContent := `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="RunManager">
    <configuration name="go build my_project" type="GoApplicationRunConfiguration" factoryName="Go Application" temporary="true" nameIsGenerated="true">
      <module name="my_project"/>
      <working_directory value="$PROJECT_DIR$"/>
      <parameters value="do work"/>
      <envs>
		<env name="GH_TOKEN" value="ghp_1234567890123456789012345678901234567890"/>
      </envs>
      <kind value="PACKAGE"/>
      <package value="package_name"/>
      <directory value="$PROJECT_DIR$"/>
      <filePath value="$PROJECT_DIR$/main.go"/>
      <method v="2"/>
    </configuration>
    <configuration name="go build my_project 1" type="GoApplicationRunConfiguration" factoryName="Go Application" temporary="true" nameIsGenerated="true">
      <module name="my_project"/>
      <working_directory value="$PROJECT_DIR$"/>
      <parameters value="upload --token npm_abcdefghijklmnopqrstuvwxyz1234567890"/>
      <envs>
      </envs>
      <kind value="PACKAGE"/>
      <package value="package_name"/>
      <directory value="$PROJECT_DIR$"/>
      <filePath value="$PROJECT_DIR$/main.go"/>
      <method v="2"/>
    </configuration>
  </component>
</project>
`

	err := os.Mkdir(filepath.Join(tmpDir, ".idea"), 0700)
	require.NoError(t, err)

	err = os.WriteFile(workspacePath, []byte(workspaceContent), 0600)
	require.NoError(t, err)

	// Create detector registry with GitHub PAT and NPM token detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewJetBrainsProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process the workspace file
	findings := probe.processWorkspaceFile(ctx, workspacePath)

	// Should find GitHub PAT and NPM token
	assert.GreaterOrEqual(t, len(findings), 2)

	// Verify metadata includes config_name and env_var
	// and findings in different configurations
	for _, finding := range findings {
		if finding.ID == "github-token-classic-pat" {
			assert.Equal(t, "GH_TOKEN", finding.Metadata["env_var"])
			assert.Equal(t, "go build my_project", finding.Metadata["config_name"])
		}
		if finding.ID == "npm-token-npm-auth-token" {
			assert.Equal(t, "go build my_project 1", finding.Metadata["config_name"])
		}
	}
}
