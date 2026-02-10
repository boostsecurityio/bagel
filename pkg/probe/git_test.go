// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestParseGitConfig(t *testing.T) {
	output := `user.name=John Doe
user.email=john@example.com
http.sslverify=false
credential.helper=store`

	config := parseGitConfig(output)

	assert.Equal(t, "John Doe", config["user.name"])
	assert.Equal(t, "john@example.com", config["user.email"])
	assert.Equal(t, "false", config["http.sslverify"])
	assert.Equal(t, "store", config["credential.helper"])
}

func TestCheckSSLVerify(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "SSL verify disabled",
			config:    map[string]string{"http.sslverify": "false"},
			wantCount: 1,
		},
		{
			name:      "SSL verify enabled",
			config:    map[string]string{"http.sslverify": "true"},
			wantCount: 0,
		},
		{
			name:      "SSL verify not set",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name:      "SSL verify disabled case insensitive",
			config:    map[string]string{"http.sslverify": "FALSE"},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkSSLVerify(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-ssl-verify-disabled", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckSSHConfig(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
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
			name:      "StrictHostKeyChecking disabled",
			config:    map[string]string{"core.sshcommand": "ssh -o StrictHostKeyChecking=no"},
			wantCount: 1,
			wantID:    "git-ssh-no-host-key-check",
		},
		{
			name:      "UserKnownHostsFile disabled",
			config:    map[string]string{"core.sshcommand": "ssh -o UserKnownHostsFile=/dev/null"},
			wantCount: 1,
			wantID:    "git-ssh-no-known-hosts",
		},
		{
			name: "Both disabled",
			config: map[string]string{
				"core.sshcommand": "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null",
			},
			wantCount: 2,
		},
		{
			name:      "Safe SSH config",
			config:    map[string]string{"core.sshcommand": "ssh"},
			wantCount: 0,
		},
		{
			name:      "No SSH config",
			config:    map[string]string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkSSHConfig(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount == 1 && tt.wantID != "" {
				assert.Equal(t, tt.wantID, findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckCredentialStorage(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "Plaintext credential storage",
			config:    map[string]string{"credential.helper": "store"},
			wantCount: 1,
		},
		{
			name:      "Secure credential storage - osxkeychain",
			config:    map[string]string{"credential.helper": "osxkeychain"},
			wantCount: 0,
		},
		{
			name:      "Secure credential storage - wincred",
			config:    map[string]string{"credential.helper": "wincred"},
			wantCount: 0,
		},
		{
			name:      "Cache storage (safe)",
			config:    map[string]string{"credential.helper": "cache"},
			wantCount: 0,
		},
		{
			name:      "No credential helper",
			config:    map[string]string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkCredentialStorage(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-credential-plaintext", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
			}
		})
	}
}

func TestCheckProtocolSettings(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "Dangerous ext protocol",
			config:    map[string]string{"protocol.ext.allow": "always"},
			wantCount: 1,
		},
		{
			name:      "Dangerous file protocol",
			config:    map[string]string{"protocol.file.allow": "always"},
			wantCount: 1,
		},
		{
			name:      "Multiple dangerous protocols",
			config:    map[string]string{"protocol.ext.allow": "always", "protocol.fd.allow": "always"},
			wantCount: 2,
		},
		{
			name:      "Safe protocol settings",
			config:    map[string]string{"protocol.https.allow": "always"},
			wantCount: 0,
		},
		{
			name:      "Protocol not always allowed",
			config:    map[string]string{"protocol.ext.allow": "user"},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkProtocolSettings(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-dangerous-protocol", findings[0].ID)
				assert.Equal(t, "medium", findings[0].Severity)
			}
		})
	}
}

func TestCheckFsckSettings(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "Transfer fsck disabled",
			config:    map[string]string{"transfer.fsckobjects": "false"},
			wantCount: 1,
		},
		{
			name:      "Fetch fsck disabled",
			config:    map[string]string{"fetch.fsckobjects": "false"},
			wantCount: 1,
		},
		{
			name:      "Receive fsck disabled",
			config:    map[string]string{"receive.fsckobjects": "false"},
			wantCount: 1,
		},
		{
			name: "Multiple fsck disabled",
			config: map[string]string{
				"transfer.fsckobjects": "false",
				"fetch.fsckobjects":    "false",
			},
			wantCount: 2,
		},
		{
			name:      "Fsck enabled",
			config:    map[string]string{"transfer.fsckobjects": "true"},
			wantCount: 0,
		},
		{
			name:      "No fsck config",
			config:    map[string]string{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkFsckSettings(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-fsck-disabled", findings[0].ID)
				assert.Equal(t, "medium", findings[0].Severity)
			}
		})
	}
}

func TestCheckProxySettings(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "HTTP proxy configured",
			config:    map[string]string{"http.proxy": "http://proxy.example.com:8080"},
			wantCount: 1,
		},
		{
			name:      "HTTPS proxy configured",
			config:    map[string]string{"https.proxy": "https://proxy.example.com:8443"},
			wantCount: 1,
		},
		{
			name:      "Git proxy configured",
			config:    map[string]string{"core.gitproxy": "proxy-command"},
			wantCount: 1,
		},
		{
			name: "Multiple proxies",
			config: map[string]string{
				"http.proxy":  "http://proxy.example.com:8080",
				"https.proxy": "https://proxy.example.com:8443",
			},
			wantCount: 2,
		},
		{
			name:      "No proxy configured",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name:      "Empty proxy value",
			config:    map[string]string{"http.proxy": ""},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkProxySettings(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-proxy-configured", findings[0].ID)
				assert.Equal(t, "low", findings[0].Severity)
			}
		})
	}
}

func TestCheckHooksPath(t *testing.T) {
	registry := detector.NewRegistry()
	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name:      "Custom hooks path",
			config:    map[string]string{"core.hookspath": "/custom/hooks"},
			wantCount: 1,
		},
		{
			name:      "No hooks path",
			config:    map[string]string{},
			wantCount: 0,
		},
		{
			name:      "Empty hooks path",
			config:    map[string]string{"core.hookspath": ""},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.checkHooksPath(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, "git-custom-hooks-path", findings[0].ID)
				assert.Equal(t, "medium", findings[0].Severity)
			}
		})
	}
}

func TestScanGitConfigForSecrets(t *testing.T) {
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := &GitProbe{
		enabled:          true,
		config:           models.ProbeSettings{Enabled: true},
		detectorRegistry: registry,
	}

	tests := []struct {
		name      string
		config    map[string]string
		wantCount int
	}{
		{
			name: "GitHub token in URL",
			config: map[string]string{
				"url.git@github.com.insteadof": "https://ghp_1234567890123456789012345678901234AB@github.com",
			},
			wantCount: 1,
		},
		{
			name: "GitHub token in header",
			config: map[string]string{
				"http.extraheader": "Authorization: Bearer gho_1234567890123456789012345678901234AB",
			},
			wantCount: 1,
		},
		{
			name: "Multiple secrets",
			config: map[string]string{
				"url.git@github.com.insteadof": "https://ghp_1234567890123456789012345678901234AB@github.com",
				"http.extraheader":             "Authorization: Bearer gho_1234567890123456789012345678901234AB",
			},
			wantCount: 2,
		},
		{
			name: "No secrets",
			config: map[string]string{
				"user.name":  "John Doe",
				"user.email": "john@example.com",
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := probe.scanGitConfigForSecrets(tt.config)
			assert.Len(t, findings, tt.wantCount)

			if tt.wantCount > 0 {
				// Verify findings are from the detector
				assert.Contains(t, findings[0].ID, "github-token")
				assert.Equal(t, "critical", findings[0].Severity)
			}
		})
	}
}
