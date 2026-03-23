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

func TestAICliProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewAICliProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "ai_cli", probe.Name())
}

func TestAICliProbe_IsEnabled(t *testing.T) {
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
			probe := NewAICliProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestAICliProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()
	registry := detector.NewRegistry()

	probe := NewAICliProbe(models.ProbeSettings{Enabled: true}, registry)

	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestAICliProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create Gemini oauth credentials file
	geminiCredsPath := filepath.Join(tmpDir, ".gemini", "oauth_creds.json")
	geminiCredsContent := `{
  "access_token": "wc37.c0ZKMQu_D5cqdBDXZdhi0_43GUfcsrLN-LWhmIjpbApo_Tu3x8tFCmeK9-YTMlNxY5oTHA6tafPaz5QD3kQiWa5HQ08KBBxM_GzB3WrTrNOHwvtph_6ekDKC7AA__xPBJim8RBiTf0MdxjK4qMT6zNlldI43rRtY3d-aDdhi55ChFKvaAXjTVIXZPr_gKVSN_V4n7O-JKM1Fu0ABcIuWGZBWEZYiERBAUT3MaQKCdjr-g__wREJDlJwZOIZ0312",
  "scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cloud-platform openid https://www.googleapis.com/auth/userinfo.email",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
  "expiry_date": 1769493476883,
  "refresh_token": "3bHz6g1UNFeQ9dP+bTQ0J6D2wDc0Xdg9y7v++kIP3XMnFw9VP8ADvC38pHAdZu7NEYLDt4Tef60bc16Zka8MiA=="
}`

	err := os.Mkdir(filepath.Join(tmpDir, ".gemini"), 0700)
	require.NoError(t, err)

	err = os.WriteFile(geminiCredsPath, []byte(geminiCredsContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("gemini_credentials", geminiCredsPath)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	// Create probe
	probe := NewAICliProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	// Should find JWT token
	assert.Len(t, findings, 1)

	// Verify metadata uses correct token type
	finding := findings[0]
	assert.Equal(t, "jwt-jwt-token", finding.ID)
	assert.Equal(t, "jwt-token", finding.Metadata["token_type"])
}

func TestAICliProbe_OversizedFileSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a chat file that exceeds the 1MB size limit
	chatDir := filepath.Join(tmpDir, ".claude", "projects", "test-session")
	err := os.MkdirAll(chatDir, 0700)
	require.NoError(t, err)

	chatPath := filepath.Join(chatDir, "conversation.jsonl")
	// Each line ~130 chars; repeat enough times to exceed 1MB
	line := `{"type":"text","content":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.placeholder"}` + "\n"
	largeContent := strings.Repeat(line, 12000) // ~1.2MB
	err = os.WriteFile(chatPath, []byte(largeContent), 0600)
	require.NoError(t, err)

	// Confirm the file is actually over the limit
	info, err := os.Stat(chatPath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(maxChatFileSize), "test file must exceed maxChatFileSize")

	// Build file index pointing at the oversized file
	index := fileindex.NewFileIndex()
	index.Add("claude_chats", chatPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAICliProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	assert.Empty(t, findings, "oversized chat file must be skipped entirely")
}
