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

func TestParsePyPIRC(t *testing.T) {
	content := `[distutils]
index-servers =
    pypi
    testpypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw`

	config := parsePyPIRC(content)

	assert.Equal(t, "https://upload.pypi.org/legacy/", config["repository"])
	assert.Equal(t, "__token__", config["username"])
	assert.Equal(t, "pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw", config["password"])
}

func TestParsePyPIRC_Comments(t *testing.T) {
	content := `# A comment
[pypi]
; Another comment
repository = https://upload.pypi.org/legacy/`

	config := parsePyPIRC(content)

	assert.Equal(t, "https://upload.pypi.org/legacy/", config["repository"])
	assert.Len(t, config, 1)
}

func TestCheckPyPIConfig(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &PyPIProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
		wantIDs   []string
	}{
		{
			name:      "plaintext password",
			config:    map[string]string{"password": "my-secret-password"},
			wantCount: 1,
			wantIDs:   []string{"pypi-plaintext-password"},
		},
		{
			name:      "insecure HTTP repository",
			config:    map[string]string{"repository": "http://insecure.example.com/simple/"},
			wantCount: 1,
			wantIDs:   []string{"pypi-insecure-repository"},
		},
		{
			name:      "HTTPS repository (safe)",
			config:    map[string]string{"repository": "https://upload.pypi.org/legacy/"},
			wantCount: 0,
		},
		{
			name: "both password and insecure repo",
			config: map[string]string{
				"password":   "my-secret-password",
				"repository": "http://insecure.example.com/simple/",
			},
			wantCount: 2,
			wantIDs:   []string{"pypi-plaintext-password", "pypi-insecure-repository"},
		},
		{
			name:      "no issues",
			config:    map[string]string{"username": "__token__", "repository": "https://upload.pypi.org/legacy/"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkPyPIConfig("test.pypirc", tt.config)
			assert.Len(t, findings, tt.wantCount)

			if len(tt.wantIDs) > 0 {
				ids := make(map[string]bool)
				for _, f := range findings {
					ids[f.ID] = true
				}
				for _, id := range tt.wantIDs {
					assert.True(t, ids[id], "Expected finding ID %s", id)
				}
			}
		})
	}
}

func TestCheckPipConfig(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &PyPIProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
		wantID    string
	}{
		{
			name:      "index-url with embedded credentials",
			config:    map[string]string{"index-url": "https://user:pass@pypi.example.com/simple/"},
			wantCount: 1,
			wantID:    "pip-index-embedded-credentials",
		},
		{
			name:      "extra-index-url with embedded credentials",
			config:    map[string]string{"extra-index-url": "https://user:pass@pypi.example.com/simple/"},
			wantCount: 1,
			wantID:    "pip-index-embedded-credentials",
		},
		{
			name:      "index-url without credentials (safe)",
			config:    map[string]string{"index-url": "https://pypi.org/simple/"},
			wantCount: 0,
		},
		{
			name:      "no index-url",
			config:    map[string]string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkPipConfig("pip.conf", tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantID, findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestPyPIProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test .pypirc
	pypircPath := filepath.Join(tmpDir, ".pypirc")
	pypircContent := `[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw`
	err := os.WriteFile(pypircPath, []byte(pypircContent), 0600)
	require.NoError(t, err)

	index := fileindex.NewFileIndex()
	index.Add("pypirc", pypircPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewPyPITokenDetector())

	probe := NewPyPIProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Should find:
	// 1. Plaintext password misconfiguration
	// 2. PyPI API token via detector
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
	}
	assert.True(t, findingIDs["pypi-plaintext-password"], "Should detect plaintext password")
	assert.True(t, findingIDs["pypi-api-token"], "Should detect PyPI API token")
}

func TestPyPIProbe_ExecutePipConfig(t *testing.T) {
	tmpDir := t.TempDir()

	pipConfPath := filepath.Join(tmpDir, "pip.conf")
	pipConfContent := `[global]
index-url = https://user:secretpass@pypi.example.com/simple/`
	err := os.WriteFile(pipConfPath, []byte(pipConfContent), 0600)
	require.NoError(t, err)

	index := fileindex.NewFileIndex()
	index.Add("pip_config", pipConfPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewPyPITokenDetector())

	probe := NewPyPIProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)

	hasEmbeddedCreds := false
	for _, f := range findings {
		if f.ID == "pip-index-embedded-credentials" {
			hasEmbeddedCreds = true
			assert.Equal(t, "high", f.Severity)
		}
	}
	assert.True(t, hasEmbeddedCreds, "Should detect embedded credentials in pip index URL")
}

func TestPyPIProbe_ExecuteWithoutFileIndex(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewPyPIProbe(models.ProbeSettings{Enabled: true}, registry)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestPyPIProbe_FileReadError(t *testing.T) {
	index := fileindex.NewFileIndex()
	index.Add("pypirc", "/path/to/nonexistent/.pypirc")

	registry := detector.NewRegistry()
	probe := NewPyPIProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestPyPIProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewPyPIProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "pypi", probe.Name())
}

func TestPyPIProbe_IsEnabled(t *testing.T) {
	registry := detector.NewRegistry()

	tests := []struct {
		name    string
		enabled bool
	}{
		{"Probe enabled", true},
		{"Probe disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := NewPyPIProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}
