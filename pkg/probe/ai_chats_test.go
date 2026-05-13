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

// Chunk C: REPL history / paste / session-env / OpenCode session
// patterns all route through ai_chats. One test per pattern bucket
// gives us a regression net against the slice drifting out of sync
// with the file index patterns.

func TestAIChatsProbe_DetectsClaudeREPLHistory(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := filepath.Join(tmpDir, "history.jsonl")
	require.NoError(t, os.WriteFile(path,
		[]byte(`{"display":"please use `+pat+` for the API","timestamp":1759181670089}`),
		0600))

	idx := fileindex.NewFileIndex()
	idx.Add("claude_repl_history", path)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	assert.Equal(t, "github-token-classic-pat", findings[0].ID)
}

func TestAIChatsProbe_DetectsClaudePasteCache(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := filepath.Join(tmpDir, "0ec4da028dc1b738.txt")
	require.NoError(t, os.WriteFile(path, []byte(pat), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("claude_paste_cache", path)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	assert.Equal(t, "github-token-classic-pat", findings[0].ID)
}

func TestAIChatsProbe_DetectsClaudeSessionEnv(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := filepath.Join(tmpDir, "12ffc74a-c66f-4ab1-a851-16b70c04bca7")
	require.NoError(t, os.WriteFile(path, []byte("GITHUB_TOKEN="+pat+"\n"), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("claude_session_env", path)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
}

func TestAIChatsProbe_DetectsCodexREPLHistory(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := filepath.Join(tmpDir, "history.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(`{"prompt":"`+pat+`"}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("codex_repl_history", path)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
}

func TestAIChatsProbe_DetectsOpenCodeSessionInfoAndMessage(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"

	infoPath := filepath.Join(tmpDir, "info.json")
	require.NoError(t, os.WriteFile(infoPath,
		[]byte(`{"id":"sess","note":"pasted `+pat+`"}`), 0600))
	msgPath := filepath.Join(tmpDir, "msg.json")
	require.NoError(t, os.WriteFile(msgPath,
		[]byte(`{"role":"user","text":"`+pat+`"}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("opencode_session_info", infoPath)
	idx.Add("opencode_session_message", msgPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewAIChatsProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 2, "info + message must both surface")
}
