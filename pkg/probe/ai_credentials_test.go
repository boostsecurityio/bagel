// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAICredentialsProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewAICredentialsProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "ai_credentials", probe.Name())
}

func TestAICredentialsProbe_IsEnabled(t *testing.T) {
	registry := detector.NewRegistry()

	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "Probe enabled", enabled: true},
		{name: "Probe disabled", enabled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := NewAICredentialsProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestAICredentialsProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()
	registry := detector.NewRegistry()

	probe := NewAICredentialsProbe(models.ProbeSettings{Enabled: true}, registry)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestAICredentialsProbe_DetectsTokensInGeminiCreds(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	geminiCredsPath := filepath.Join(tmpDir, ".gemini", "oauth_creds.json")
	geminiCredsContent := `{
  "access_token": "wc37.c0ZKMQu_D5cqdBDXZdhi0_43GUfcsrLN-LWhmIjpbApo_Tu3x8tFCmeK9-YTMlNxY5oTHA6tafPaz5QD3kQiWa5HQ08KBBxM_GzB3WrTrNOHwvtph_6ekDKC7AA__xPBJim8RBiTf0MdxjK4qMT6zNlldI43rRtY3d-aDdhi55ChFKvaAXjTVIXZPr_gKVSN_V4n7O-JKM1Fu0ABcIuWGZBWEZYiERBAUT3MaQKCdjr-g__wREJDlJwZOIZ0312",
  "id_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg"
}`

	require.NoError(t, os.Mkdir(filepath.Join(tmpDir, ".gemini"), 0700))
	require.NoError(t, os.WriteFile(geminiCredsPath, []byte(geminiCredsContent), 0600))

	index := fileindex.NewFileIndex()
	index.Add("gemini_credentials", geminiCredsPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAICredentialsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, "jwt-jwt-token", findings[0].ID)
}

func TestAICredentialsProbe_OversizedFileSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	credsPath := filepath.Join(tmpDir, "auth.json")
	// Each line ~130 chars; repeat enough times to exceed 1MB
	line := `{"type":"text","content":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.placeholder"}` + "\n"
	largeContent := strings.Repeat(line, 12000) // ~1.2MB
	require.NoError(t, os.WriteFile(credsPath, []byte(largeContent), 0600))

	info, err := os.Stat(credsPath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(defaultAICredsMaxFileSize))

	index := fileindex.NewFileIndex()
	index.Add("opencode_credentials", credsPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAICredentialsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	assert.Empty(t, findings, "oversized credential file must be skipped entirely")
}

func TestAICredentialsProbe_CustomMaxFileSizeFlag(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	credsPath := filepath.Join(tmpDir, "auth.json")
	// 2 KB — would pass the default 1 MB but exceed a 1 KB custom limit
	require.NoError(t, os.WriteFile(credsPath, []byte(strings.Repeat("x", 2*1024)), 0600))

	index := fileindex.NewFileIndex()
	index.Add("codex_credentials", credsPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAICredentialsProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, findings, "file exceeding custom max_file_size must be skipped")
}
