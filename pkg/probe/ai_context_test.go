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

func newContextRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	reg.Register(detector.NewGitHubPATDetector())
	reg.Register(detector.NewSlackTokenDetector())
	reg.Register(detector.NewGenericAPIKeyDetector())
	return reg
}

func TestContextProbe_CatchesSecretsInProjectClaudeMD(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "some-repo")
	require.NoError(t, os.MkdirAll(repoDir, 0700))

	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	claudeMD := filepath.Join(repoDir, "CLAUDE.md")
	require.NoError(t, os.WriteFile(claudeMD, []byte(`# Project Notes
Use this token for the GitHub MCP server when prompted:

GITHUB_TOKEN=`+pat+`

Otherwise, ask the user.
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("ai_memory_md", claudeMD)

	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	var pat_finding *models.Finding
	for i := range findings {
		if findings[i].Metadata["token_type"] == "classic-pat" {
			pat_finding = &findings[i]
		}
	}
	require.NotNil(t, pat_finding, "expected PAT finding from CLAUDE.md")
	assert.Equal(t, "ai_context", pat_finding.Probe)
	assert.NotZero(t, pat_finding.Metadata["line_number"], "line_number must be set by per-line scan")
}

func TestContextProbe_CatchesSecretsInAGENTS_MD(t *testing.T) {
	tmpDir := t.TempDir()
	agentsMD := filepath.Join(tmpDir, "AGENTS.md")
	slack := "xoxb-1111111111-2222222222-aaaaaaaaaaaaaaaaaaaaaaaa"
	require.NoError(t, os.WriteFile(agentsMD, []byte(`# Agents
Bot token: `+slack+`
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("ai_memory_md", agentsMD)

	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	hasSlack := false
	for _, f := range findings {
		if f.ID == "slack-token" {
			hasSlack = true
		}
	}
	assert.True(t, hasSlack, "expected slack-token finding from AGENTS.md")
}

func TestContextProbe_NoSecrets_NoFindings(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "CLAUDE.md")
	require.NoError(t, os.WriteFile(path, []byte("# Project notes\n\nNothing sensitive here.\n"), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("ai_memory_md", path)

	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestContextProbe_SkipsOversized(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "CLAUDE.md")
	require.NoError(t, os.WriteFile(path, make([]byte, 4096), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("ai_memory_md", path)

	probe := NewContextProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestContextProbe_NoFileIndexReturnsNothing(t *testing.T) {
	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestContextProbe_ScansAllAgentContextPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"

	// One file per pattern bucket. Filenames are arbitrary — the
	// pattern key (not the filename) controls which probe input they
	// land in.
	cases := []struct {
		pattern string
		name    string
	}{
		{"claude_commands", "deploy.md"},
		{"claude_agents", "tester.md"},
		{"claude_skills", "SKILL.md"},
		{"agents_skills", "SKILL.md"},
		{"codex_instructions", "instructions.md"},
		{"codex_memories", "auth.md"},
		{"codex_skills", "SKILL.md"},
	}

	idx := fileindex.NewFileIndex()
	for i, c := range cases {
		// Distinct content per file so duplicate-fingerprint dedup
		// doesn't collapse them.
		path := filepath.Join(tmpDir, c.name+"-"+c.pattern)
		body := "GH_TOKEN_" + c.pattern + "=" + pat + "X" + string(rune('0'+i))
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		idx.Add(c.pattern, path)
	}

	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), len(cases),
		"expected at least one finding per pattern bucket, got %d", len(findings))

	// Every finding should be attributed to ai_context.
	for _, f := range findings {
		assert.Equal(t, "ai_context", f.Probe)
	}
}

func TestContextProbe_DeduplicatesPathsAcrossPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := filepath.Join(tmpDir, "shared.md")
	require.NoError(t, os.WriteFile(path, []byte("token="+pat), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("ai_memory_md", path)
	idx.Add("claude_commands", path) // same path, two patterns

	probe := NewContextProbe(models.ProbeSettings{Enabled: true}, newContextRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	count := 0
	for _, f := range findings {
		if f.Metadata["token_type"] == "classic-pat" {
			count++
		}
	}
	assert.Equal(t, 1, count, "same path matched under multiple patterns must be scanned once")
}
