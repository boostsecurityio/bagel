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

func TestAIChatsProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "ai_chats", probe.Name())
}

func TestAIChatsProbe_IsEnabled(t *testing.T) {
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
			probe := NewAIChatsProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestAIChatsProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()
	registry := detector.NewRegistry()

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestAIChatsProbe_DetectsTokensInClaudeChats(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	chatDir := filepath.Join(tmpDir, ".claude", "projects", "test-session")
	require.NoError(t, os.MkdirAll(chatDir, 0700))

	chatPath := filepath.Join(chatDir, "conversation.jsonl")
	chatContent := `{"role":"user","content":"my token is ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}` + "\n" +
		`{"role":"assistant","content":"please don't share secrets"}` + "\n"
	require.NoError(t, os.WriteFile(chatPath, []byte(chatContent), 0600))

	index := fileindex.NewFileIndex()
	index.Add("claude_chats", chatPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	require.NotEmpty(t, findings, "Should detect GitHub PAT in chat")
	assert.Equal(t, "github-token-classic-pat", findings[0].ID)
}

func TestAIChatsProbe_OversizedFileSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	chatDir := filepath.Join(tmpDir, ".claude", "projects", "test-session")
	require.NoError(t, os.MkdirAll(chatDir, 0700))

	chatPath := filepath.Join(chatDir, "conversation.jsonl")
	line := `{"type":"text","content":"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.placeholder"}` + "\n"
	largeContent := strings.Repeat(line, 12000) // ~1.2MB
	require.NoError(t, os.WriteFile(chatPath, []byte(largeContent), 0600))

	info, err := os.Stat(chatPath)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(defaultAIChatsMaxFileSize))

	index := fileindex.NewFileIndex()
	index.Add("claude_chats", chatPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)

	assert.Empty(t, findings, "oversized chat file must be skipped entirely")
}

func TestAIChatsProbe_CustomMaxFileSizeFlag(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	chatDir := filepath.Join(tmpDir, ".claude", "projects", "test-session")
	require.NoError(t, os.MkdirAll(chatDir, 0700))

	chatPath := filepath.Join(chatDir, "conversation.jsonl")
	require.NoError(t, os.WriteFile(chatPath, []byte(strings.Repeat("x", 2*1024)), 0600))

	index := fileindex.NewFileIndex()
	index.Add("claude_chats", chatPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewJWTDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, registry)
	probe.SetFileIndex(index)

	findings, err := probe.Execute(ctx)
	require.NoError(t, err)
	assert.Empty(t, findings, "file exceeding custom max_file_size must be skipped")
}
