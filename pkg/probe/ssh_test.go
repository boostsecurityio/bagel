// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckSSHConfigContent_StrictHostKeyChecking(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &SSHProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		content   string
		wantCount int
		wantID    string
	}{
		{
			name: "StrictHostKeyChecking disabled globally",
			content: `Host *
    StrictHostKeyChecking no`,
			wantCount: 1,
			wantID:    "ssh-strict-host-key-checking-disabled",
		},
		{
			name: "StrictHostKeyChecking enabled",
			content: `Host *
    StrictHostKeyChecking yes`,
			wantCount: 0,
		},
		{
			name: "StrictHostKeyChecking disabled in multiple hosts",
			content: `Host github.com
    StrictHostKeyChecking no

Host example.com
    StrictHostKeyChecking no

Host safe.com
    StrictHostKeyChecking yes`,
			wantCount: 2, // Should catch both insecure hosts
			wantID:    "ssh-strict-host-key-checking-disabled",
		},
		{
			name: "StrictHostKeyChecking disabled then safe",
			content: `Host unsafe.com
    StrictHostKeyChecking no

Host safe.com
    StrictHostKeyChecking yes`,
			wantCount: 1,
			wantID:    "ssh-strict-host-key-checking-disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkSSHConfigContent("test_config", tt.content)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantID, findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
				// Verify metadata includes host pattern and line number
				assert.NotNil(t, findings[0].Metadata["host_pattern"])
				assert.NotNil(t, findings[0].Metadata["line_number"])
			}
		})
	}
}

func TestCheckSSHConfigContent_UserKnownHostsFile(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &SSHProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		content   string
		wantCount int
		wantID    string
	}{
		{
			name: "Known hosts disabled with /dev/null",
			content: `Host *
    UserKnownHostsFile /dev/null`,
			wantCount: 1,
			wantID:    "ssh-known-hosts-disabled",
		},
		{
			name: "Known hosts disabled with /dev/NULL (uppercase)",
			content: `Host *
    UserKnownHostsFile /dev/NULL`,
			wantCount: 1,
			wantID:    "ssh-known-hosts-disabled",
		},
		{
			name: "Known hosts disabled with /Dev/Null (mixed case)",
			content: `Host *
    UserKnownHostsFile /Dev/Null`,
			wantCount: 1,
			wantID:    "ssh-known-hosts-disabled",
		},
		{
			name: "Known hosts disabled with NUL (Windows)",
			content: `Host *
    UserKnownHostsFile NUL`,
			wantCount: 1,
			wantID:    "ssh-known-hosts-disabled",
		},
		{
			name: "Known hosts disabled with C:\\nul (Windows path)",
			content: `Host *
    UserKnownHostsFile C:\nul`,
			wantCount: 1,
			wantID:    "ssh-known-hosts-disabled",
		},
		{
			name: "Normal known hosts file",
			content: `Host *
    UserKnownHostsFile ~/.ssh/known_hosts`,
			wantCount: 0,
		},
		{
			name: "Known hosts disabled in multiple hosts",
			content: `Host unsafe1.com
    UserKnownHostsFile /dev/null

Host unsafe2.com
    UserKnownHostsFile /dev/NULL`,
			wantCount: 2,
			wantID:    "ssh-known-hosts-disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkSSHConfigContent("test_config", tt.content)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantID, findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckSSHConfigContent_ForwardAgent(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &SSHProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		content   string
		wantCount int
		wantID    string
	}{
		{
			name: "ForwardAgent enabled globally",
			content: `Host *
    ForwardAgent yes`,
			wantCount: 1,
			wantID:    "ssh-forward-agent-enabled",
		},
		{
			name: "ForwardAgent disabled",
			content: `Host *
    ForwardAgent no`,
			wantCount: 0,
		},
		{
			name: "ForwardAgent enabled for specific host",
			content: `Host github.com
    ForwardAgent yes`,
			wantCount: 1,
			wantID:    "ssh-forward-agent-enabled",
		},
		{
			name: "ForwardAgent enabled for multiple hosts",
			content: `Host host1.com
    ForwardAgent yes

Host host2.com
    ForwardAgent yes`,
			wantCount: 2,
			wantID:    "ssh-forward-agent-enabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkSSHConfigContent("test_config", tt.content)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, tt.wantID, findings[0].ID)
				assert.Equal(t, "medium", findings[0].Severity)
			}
		})
	}
}

func TestCheckKeyPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	registry := detector.NewRegistry()
	probe := &SSHProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name        string
		permissions os.FileMode
		wantCount   int
	}{
		{
			name:        "Secure permissions 0600",
			permissions: 0600,
			wantCount:   0,
		},
		{
			name:        "Secure permissions 0400",
			permissions: 0400,
			wantCount:   0,
		},
		{
			name:        "Insecure permissions 0644",
			permissions: 0644,
			wantCount:   1,
		},
		{
			name:        "Insecure permissions 0777",
			permissions: 0777,
			wantCount:   1,
		},
		{
			name:        "Insecure permissions 0640",
			permissions: 0640,
			wantCount:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip insecure permission tests on Windows - Unix permission bits don't apply
			if runtime.GOOS == "windows" && tt.wantCount > 0 {
				t.Skip("Unix file permissions not applicable on Windows")
			}

			// Create a temporary key file with specific permissions
			keyPath := filepath.Join(tmpDir, tt.name+".key")
			err := os.WriteFile(keyPath, []byte("test key"), tt.permissions)
			require.NoError(t, err)

			findings := probe.checkKeyPermissions(ctx, keyPath)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "ssh-key-insecure-permissions", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
				assert.Contains(t, findings[0].Message, "has permissions")
			}
		})
	}
}

func TestSSHProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create test SSH config file
	sshDir := filepath.Join(tmpDir, ".ssh")
	err := os.MkdirAll(sshDir, 0700)
	require.NoError(t, err)

	configPath := filepath.Join(sshDir, "config")
	configContent := `Host *
    StrictHostKeyChecking no
    ForwardAgent yes`
	err = os.WriteFile(configPath, []byte(configContent), 0600)
	require.NoError(t, err)

	// Create unencrypted SSH key with bad permissions
	keyPath := filepath.Join(sshDir, "id_rsa")
	keyContent := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`
	err = os.WriteFile(keyPath, []byte(keyContent), 0644)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("ssh_config", configPath)
	index.Add("ssh_keys", keyPath)

	// Create detector registry with SSH private key detector
	registry := detector.NewRegistry()
	registry.Register(detector.NewSSHPrivateKeyDetector())

	// Create SSH probe
	probe := NewSSHProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, findings)

	// Should find at least:
	// 1. StrictHostKeyChecking disabled
	// 2. ForwardAgent enabled
	// 3. Insecure key permissions (Unix only)
	// 4. Unencrypted private key
	expectedMinFindings := 4
	if runtime.GOOS == "windows" {
		expectedMinFindings = 3 // No permission findings on Windows
	}
	assert.GreaterOrEqual(t, len(findings), expectedMinFindings)

	// Check for expected findings
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
	}

	assert.True(t, findingIDs["ssh-strict-host-key-checking-disabled"])
	assert.True(t, findingIDs["ssh-forward-agent-enabled"])
	if runtime.GOOS != "windows" {
		assert.True(t, findingIDs["ssh-key-insecure-permissions"])
	}
	assert.True(t, findingIDs["ssh-private-key-rsa"])
}

func TestSSHProbe_ExecuteWithoutFileIndex(t *testing.T) {
	ctx := context.Background()

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewSSHPrivateKeyDetector())

	// Create SSH probe without setting file index
	probe := NewSSHProbe(models.ProbeSettings{Enabled: true}, registry)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings without file index")
}

func TestSSHProbe_ProcessSSHKey_SkipPublicKeys(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create a public key file
	pubKeyPath := filepath.Join(tmpDir, "id_rsa.pub")
	pubKeyContent := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."
	err := os.WriteFile(pubKeyPath, []byte(pubKeyContent), 0644)
	require.NoError(t, err)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewSSHPrivateKeyDetector())

	// Create SSH probe
	probe := NewSSHProbe(models.ProbeSettings{Enabled: true}, registry)

	// Process public key
	findings := probe.processSSHKey(ctx, pubKeyPath)

	// Should not detect anything for public keys
	assert.Empty(t, findings)
}

func TestSSHProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewSSHProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "ssh", probe.Name())
}

func TestSSHProbe_IsEnabled(t *testing.T) {
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
			probe := NewSSHProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}

func TestSSHProbe_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()

	// Create empty config file
	emptyConfigPath := filepath.Join(tmpDir, "empty_config")
	err := os.WriteFile(emptyConfigPath, []byte(""), 0600)
	require.NoError(t, err)

	// Create config with only comments
	commentsConfigPath := filepath.Join(tmpDir, "comments_config")
	commentsContent := `# This is a comment
# Another comment
# Host example.com`
	err = os.WriteFile(commentsConfigPath, []byte(commentsContent), 0600)
	require.NoError(t, err)

	// Build file index
	index := fileindex.NewFileIndex()
	index.Add("ssh_config", emptyConfigPath)
	index.Add("ssh_config", commentsConfigPath)

	// Create detector registry
	registry := detector.NewRegistry()
	registry.Register(detector.NewSSHPrivateKeyDetector())

	// Create SSH probe
	probe := NewSSHProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	// Execute probe
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	// Should return no findings for empty/comment-only files
	assert.Empty(t, findings)
}
