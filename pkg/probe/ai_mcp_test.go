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

func newMCPRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	reg.Register(detector.NewGitHubPATDetector())
	reg.Register(detector.NewSlackTokenDetector())
	reg.Register(detector.NewDatabaseConnectionDetector())
	reg.Register(detector.NewJWTDetector())
	reg.Register(detector.NewGenericAPIKeyDetector())
	return reg
}

func writeMCPConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	return path
}

func TestMCPProbe_ExtractsGitHubPATFromEnv(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := writeMCPConfig(t, tmpDir, "claude.json", `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "`+pat+`"}
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var pat_finding *models.Finding
	for i := range findings {
		if findings[i].Metadata["token_type"] == "classic-pat" {
			pat_finding = &findings[i]
			break
		}
	}
	require.NotNil(t, pat_finding, "expected GitHub PAT finding from MCP env, got: %+v", findings)
	assert.Equal(t, "github", pat_finding.Metadata["mcp_server_name"])
	assert.Equal(t, "npx", pat_finding.Metadata["mcp_server_command"])
	assert.Equal(t, "GITHUB_PERSONAL_ACCESS_TOKEN", pat_finding.Metadata["env_var"])
	assert.Contains(t, pat_finding.Metadata["location"], `mcpServers["github"].env["GITHUB_PERSONAL_ACCESS_TOKEN"]`)
	assert.Equal(t, "file:"+path, pat_finding.Path)
	assert.Equal(t, "ai_mcp", pat_finding.Probe)
}

func TestMCPProbe_ExtractsSlackTokenFromArgs(t *testing.T) {
	tmpDir := t.TempDir()
	slack := "xoxb-1111111111-2222222222-aaaaaaaaaaaaaaaaaaaaaaaa"
	path := writeMCPConfig(t, tmpDir, "settings.json", `{
  "mcpServers": {
    "slack": {
      "command": "/usr/local/bin/my-mcp-server",
      "args": ["--token", "`+slack+`"]
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_settings", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var slackFinding *models.Finding
	for i := range findings {
		if findings[i].ID == "slack-token" {
			slackFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, slackFinding, "expected slack-token finding")
	assert.Equal(t, "slack", slackFinding.Metadata["mcp_server_name"])
	assert.Contains(t, slackFinding.Metadata["location"], `mcpServers["slack"].args[1]`)
}

func TestMCPProbe_SkipsPackageNameFirstArg(t *testing.T) {
	// `@modelcontextprotocol/server-x` looks suspicious to generic
	// API-key detector heuristics; skipping the first arg when the
	// command is npx/bunx/uvx prevents that noise.
	tmpDir := t.TempDir()
	path := writeMCPConfig(t, tmpDir, ".mcp.json", `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/some/path"]
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("mcp_project_config", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "no credential present — must not emit findings")
}

func TestMCPProbe_SkipsPackageNameAfterFlags(t *testing.T) {
	// The canonical npx invocation is `npx -y @scope/pkg ...` — args[0]
	// is `-y`, args[1] is the package. Skipping only args[0] would feed
	// the package name to the generic-api-key detector. The fix is to
	// skip the first non-flag arg, which here is index 1.
	tmpDir := t.TempDir()
	path := writeMCPConfig(t, tmpDir, ".mcp.json", `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/some/path"]
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("mcp_project_config", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "package identifier at args[1] (after -y) must be skipped")
}

func TestMCPProbe_DoesNotSkipFirstArgWhenItIsNotAPackageIdent(t *testing.T) {
	// Defensive: if the first non-flag arg looks like a credential
	// (e.g. someone wired their token at the start of the args list),
	// don't silently swallow it just because the command is npx.
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := writeMCPConfig(t, tmpDir, ".mcp.json", `{
  "mcpServers": {
    "weird": {
      "command": "npx",
      "args": ["`+pat+`", "/some/path"]
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("mcp_project_config", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	hasPAT := false
	for _, f := range findings {
		if f.Metadata["token_type"] == "classic-pat" {
			hasPAT = true
			break
		}
	}
	assert.True(t, hasPAT, "PAT-shaped first arg must not be skipped")
}

func TestMCPProbe_HandlesLegacyEnvVarsKey(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "9876543210zyxwvutsrqponmlkjihgfedcba"
	path := writeMCPConfig(t, tmpDir, "claude.json", `{
  "mcpServers": {
    "legacy": {
      "command": "node",
      "args": ["server.js"],
      "envVars": {"GITHUB_TOKEN": "`+pat+`"}
    }
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	hasPAT := false
	for _, f := range findings {
		if f.Metadata["token_type"] == "classic-pat" {
			hasPAT = true
			assert.Equal(t, "GITHUB_TOKEN", f.Metadata["env_var"])
			// Location must reflect the actual source map — the legacy
			// `envVars` key — not `env`, or users will rotate the
			// wrong path.
			assert.Contains(t, f.Metadata["location"],
				`mcpServers["legacy"].envVars["GITHUB_TOKEN"]`,
				"legacy envVars findings must be attributed to envVars[…], not env[…]")
		}
	}
	assert.True(t, hasPAT)
}

func TestMCPProbe_NoMCPServers_NoFindings(t *testing.T) {
	tmpDir := t.TempDir()
	path := writeMCPConfig(t, tmpDir, "claude.json", `{
  "numStartups": 42,
  "userID": "abc",
  "otherStuff": "unrelated"
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMCPProbe_DeduplicatesPathsAcrossPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	path := writeMCPConfig(t, tmpDir, "claude.json", `{
  "mcpServers": {"x": {"command":"node","env":{"K":"`+pat+`"}}}
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)
	idx.Add("claude_settings", path) // same path indexed twice

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	patCount := 0
	for _, f := range findings {
		if f.Metadata["token_type"] == "classic-pat" {
			patCount++
		}
	}
	assert.Equal(t, 1, patCount, "same path indexed under multiple patterns must be parsed once")
}

func TestMCPProbe_MalformedJSONReturnsNoError(t *testing.T) {
	tmpDir := t.TempDir()
	path := writeMCPConfig(t, tmpDir, "claude.json", `{not json`)

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)

	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMCPProbe_OversizedSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "claude.json")
	require.NoError(t, os.WriteFile(path, make([]byte, 4096), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("claude_app_state", path)

	probe := NewMCPProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, newMCPRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMCPProbe_NoFileIndexReturnsNothing(t *testing.T) {
	probe := NewMCPProbe(models.ProbeSettings{Enabled: true}, newMCPRegistry())
	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}
