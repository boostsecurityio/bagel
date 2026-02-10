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

func TestShellHistoryProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "shell_history", probe.Name())
}

func TestShellHistoryProbe_IsEnabled(t *testing.T) {
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
			probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestShellHistoryProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()
	registry := detector.NewRegistry()

	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestShellHistoryProbe_ProcessHistoryFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test history file with secrets
	historyPath := filepath.Join(tmpDir, ".bash_history")
	historyContent := `ls -la
cd /home/user
export API_KEY=secret123
curl -H "Authorization: Bearer ghp_1234567890123456789012345678901234567890" https://api.github.com
git clone https://user:password@github.com/repo/project.git
npm publish --token npm_abcdefghijklmnopqrstuvwxyz1234567890
echo "normal command"
`

	err := os.WriteFile(historyPath, []byte(historyContent), 0600)
	require.NoError(t, err)

	// Create detector registry with GitHub PAT and NPM token detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process the history file
	findings := probe.processHistoryFile(ctx, historyPath)

	// Should find GitHub PAT and NPM token
	assert.GreaterOrEqual(t, len(findings), 2)

	// Verify metadata includes line numbers and commands
	for _, finding := range findings {
		assert.NotNil(t, finding.Metadata["line_number"])
	}
}

func TestShellHistoryProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test .bash_history
	bashHistoryPath := filepath.Join(tmpDir, ".bash_history")
	bashHistoryContent := `cd ~/projects
export GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890
git push origin main
`
	err := os.WriteFile(bashHistoryPath, []byte(bashHistoryContent), 0600)
	require.NoError(t, err)

	// Create test .zsh_history
	zshHistoryPath := filepath.Join(tmpDir, ".zsh_history")
	zshHistoryContent := `: 1234567890:0;npm config set //registry.npmjs.org/:_authToken npm_abcdefghijklmnopqrstuvwxyz1234567890
: 1234567891:0;ls -la
`
	err = os.WriteFile(zshHistoryPath, []byte(zshHistoryContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("shell_history", bashHistoryPath)
	index.Add("shell_history", zshHistoryPath)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 2)

	// Check finding types
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
		// Verify metadata
		assert.NotNil(t, f.Metadata["line_number"])
	}

	assert.True(t, findingIDs["github-token-classic-pat"], "Should detect GitHub PAT")
	assert.True(t, findingIDs["npm-token-npm-auth-token"], "Should detect NPM token")
}

func TestShellHistoryProbe_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create empty history file
	historyPath := filepath.Join(tmpDir, ".bash_history")
	err := os.WriteFile(historyPath, []byte(""), 0600)
	require.NoError(t, err)

	// Create detector registry
	registry := detector.NewRegistry()

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file
	findings := probe.processHistoryFile(ctx, historyPath)

	assert.Empty(t, findings, "Empty file should produce no findings")
}

func TestShellHistoryProbe_OnlyNormalCommands(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create history file with only normal commands
	historyPath := filepath.Join(tmpDir, ".bash_history")
	historyContent := `ls -la
cd /home/user
mkdir test_dir
echo "Hello World"
git status
npm install
docker ps
`

	err := os.WriteFile(historyPath, []byte(historyContent), 0600)
	require.NoError(t, err)

	// Create detector registry with common detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file
	findings := probe.processHistoryFile(ctx, historyPath)

	assert.Empty(t, findings, "Normal commands should not trigger any findings")
}

func TestParseHistoryLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{
			name:     "Zsh extended history format",
			line:     ": 1234567890:0;curl -H \"Authorization: Bearer token123\" https://api.example.com",
			expected: "curl -H \"Authorization: Bearer token123\" https://api.example.com",
		},
		{
			name:     "Zsh with longer duration",
			line:     ": 1234567890:42;npm config set //registry.npmjs.org/:_authToken npm_abc123",
			expected: "npm config set //registry.npmjs.org/:_authToken npm_abc123",
		},
		{
			name:     "Zsh with multidigit timestamp",
			line:     ": 1699876543:10;export API_KEY=secret123",
			expected: "export API_KEY=secret123",
		},
		{
			name:     "Bash history format (no metadata)",
			line:     "curl -u admin:password https://api.example.com",
			expected: "curl -u admin:password https://api.example.com",
		},
		{
			name:     "Bash simple command",
			line:     "ls -la",
			expected: "ls -la",
		},
		{
			name:     "Command with semicolon in content",
			line:     ": 1234567890:0;echo \"test; another test\"",
			expected: "echo \"test; another test\"",
		},
		{
			name:     "Zsh format with only colon at start",
			line:     ":1234567890:0;git status",
			expected: "git status",
		},
		{
			name:     "Empty zsh metadata (malformed)",
			line:     ":;command",
			expected: "command",
		},
		{
			name:     "Colon but no semicolon (malformed zsh)",
			line:     ": 1234567890:0 command without semicolon",
			expected: ": 1234567890:0 command without semicolon",
		},
		{
			name:     "Empty command after semicolon",
			line:     ": 1234567890:0;",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHistoryLine(tt.line)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "Short command",
			command:  "ls -la",
			expected: "ls -la",
		},
		{
			name:     "Exactly 100 chars",
			command:  strings.Repeat("a", 100),
			expected: strings.Repeat("a", 100),
		},
		{
			name:     "Long command",
			command:  strings.Repeat("a", 150),
			expected: strings.Repeat("a", 100) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateCommand(tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShellHistoryProbe_NonExistentFile(t *testing.T) {
	ctx := context.Background()

	// Create detector registry
	registry := detector.NewRegistry()

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process non-existent file
	findings := probe.processHistoryFile(ctx, "/path/that/does/not/exist/.bash_history")

	assert.Empty(t, findings, "Non-existent file should return no findings")
}

func TestShellHistoryProbe_LongCommandLine(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a very long command line (>64KB which is the default buffer)
	// This simulates a real scenario where users might have extremely long base64 strings,
	// large JSON payloads, or concatenated commands
	longToken := strings.Repeat("a", 100*1024) // 100KB token
	longCommand := "curl -H \"Authorization: Bearer ghp_1234567890123456789012345678901234567890" + longToken + "\" https://api.github.com"

	historyPath := filepath.Join(tmpDir, ".bash_history")
	historyContent := "ls -la\n" + longCommand + "\necho done\n"

	err := os.WriteFile(historyPath, []byte(historyContent), 0600)
	require.NoError(t, err)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file - should handle the long line without error
	findings := probe.processHistoryFile(ctx, historyPath)

	// Should still detect the GitHub PAT in the long command
	assert.GreaterOrEqual(t, len(findings), 1, "Should detect secret even in very long command line")

	// Verify the finding
	if len(findings) > 0 {
		assert.Equal(t, "github-token-classic-pat", findings[0].ID)
		assert.NotNil(t, findings[0].Metadata["line_number"])
	}
}

func TestShellHistoryProbe_ExtremelyLongLine(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a line that exceeds even the 1MB buffer
	// This tests the ErrTooLong error handling
	extremelyLongCommand := "echo " + strings.Repeat("x", 2*1024*1024) // 2MB

	historyPath := filepath.Join(tmpDir, ".bash_history")
	historyContent := "export GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n" + extremelyLongCommand + "\nls -la\n"

	err := os.WriteFile(historyPath, []byte(historyContent), 0600)
	require.NoError(t, err)

	// Create detector registry with GitHub PAT detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process file - should handle gracefully even with line exceeding max buffer
	// The scanner will stop when it hits ErrTooLong, but should process lines before it
	findings := probe.processHistoryFile(ctx, historyPath)

	// Should detect the GitHub token in the first line before hitting the too-long line
	// Note: Scanner stops on ErrTooLong, so subsequent lines won't be processed
	assert.GreaterOrEqual(t, len(findings), 1, "Should process lines before the too-long line")

	// Verify we got the GitHub token from the first line
	if len(findings) > 0 {
		assert.Equal(t, "github-token-classic-pat", findings[0].ID)
	}
}

func TestShellHistoryProbe_ZshHistoryParsing(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test .zsh_history with various formats
	zshHistoryPath := filepath.Join(tmpDir, ".zsh_history")
	zshHistoryContent := `: 1699876543:0;ls -la
: 1699876544:2;curl -H "Authorization: Bearer ghp_1234567890123456789012345678901234567890" https://api.github.com/user
: 1699876545:0;cd ~/projects
: 1699876546:5;export GITHUB_TOKEN=ghp_0987654321098765432109876543210987654321
: 1699876547:1;npm config set //registry.npmjs.org/:_authToken npm_abcdefghijklmnopqrstuvwxyz1234567890
: 1699876548:0;git status
`
	err := os.WriteFile(zshHistoryPath, []byte(zshHistoryContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("shell_history", zshHistoryPath)

	// Create detector registry with GitHub and NPM detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())

	// Create probe
	probe := NewShellHistoryProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 3, "Should detect multiple GitHub PATs and NPM token from zsh history")

	// Check finding details
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
		// Verify metadata includes line number and parsed command (without zsh metadata)
		assert.NotNil(t, f.Metadata["line_number"], "Finding should have line number")
	}

	// Verify we detected the expected secrets
	assert.True(t, findingIDs["github-token-classic-pat"], "Should detect GitHub PAT tokens")
	assert.True(t, findingIDs["npm-token-npm-auth-token"], "Should detect NPM token")
}
