// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
)

// GitProbe checks Git configuration for security issues
type GitProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
}

// NewGitProbe creates a new Git probe
func NewGitProbe(config models.ProbeSettings, registry *detector.Registry) *GitProbe {
	return &GitProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *GitProbe) Name() string {
	return "git"
}

// IsEnabled returns whether the probe is enabled
func (p *GitProbe) IsEnabled() bool {
	return p.enabled
}

// Execute runs the Git probe
func (p *GitProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	findings := make([]models.Finding, 0, 4)

	// Get all global git config once
	cmd := exec.CommandContext(ctx, "git", "config", "--list", "--global")
	output, err := cmd.Output()
	if err != nil {
		// Git not configured or not installed, skip
		return findings, nil
	}

	config := parseGitConfig(string(output))

	// Check git configuration for security issues
	findings = append(findings, p.checkGitConfig(config)...)

	// Scan git config for secrets using detector registry
	findings = append(findings, p.scanGitConfigForSecrets(config)...)

	return findings, nil
}

// checkGitConfig checks for insecure git configuration settings
func (p *GitProbe) checkGitConfig(config map[string]string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

	// Check for SSL verification disabled
	findings = append(findings, p.checkSSLVerify(config)...)

	// Check for insecure SSH configuration
	findings = append(findings, p.checkSSHConfig(config)...)

	// Check for plaintext credential storage
	findings = append(findings, p.checkCredentialStorage(config)...)

	// Check for insecure protocol settings
	findings = append(findings, p.checkProtocolSettings(config)...)

	// Check for disabled fsck
	findings = append(findings, p.checkFsckSettings(config)...)

	// Check for suspicious proxies
	findings = append(findings, p.checkProxySettings(config)...)

	// Check for custom hooks path
	findings = append(findings, p.checkHooksPath(config)...)

	return findings
}

// parseGitConfig parses git config output into a map
func parseGitConfig(output string) map[string]string {
	config := make(map[string]string)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			config[parts[0]] = parts[1]
		}
	}
	return config
}

// checkSSLVerify checks for disabled SSL verification
func (p *GitProbe) checkSSLVerify(config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["http.sslverify"]; ok && strings.ToLower(value) == "false" {
		findings = append(findings, models.Finding{
			ID:       "git-ssl-verify-disabled",
			Probe:    p.Name(),
			Severity: "high",
			Title:    "Git SSL Verification Disabled",
			Message:  "Git is configured to skip SSL certificate verification (http.sslVerify=false). This makes you vulnerable to man-in-the-middle attacks when cloning or pulling from HTTPS repositories.",
			Path:     "git-config:http.sslverify",
			Metadata: map[string]interface{}{
				"config_key":   "http.sslverify",
				"config_value": value,
			},
		})
	}

	return findings
}

// checkSSHConfig checks for insecure SSH configurations
func (p *GitProbe) checkSSHConfig(config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["core.sshcommand"]; ok {
		// Check for StrictHostKeyChecking disabled
		if strings.Contains(strings.ToLower(value), "stricthostkeychecking=no") ||
			strings.Contains(strings.ToLower(value), "stricthostkeychecking no") {
			findings = append(findings, models.Finding{
				ID:       "git-ssh-no-host-key-check",
				Probe:    p.Name(),
				Severity: "high",
				Title:    "Git SSH Host Key Checking Disabled",
				Message:  "Git is configured to skip SSH host key verification. This makes you vulnerable to man-in-the-middle attacks when connecting to Git repositories over SSH.",
				Path:     "git-config:core.sshcommand",
				Metadata: map[string]interface{}{
					"config_key":   "core.sshcommand",
					"config_value": value,
				},
			})
		}

		// Check for UserKnownHostsFile disabled - extract the path and use cross-platform check
		lowerValue := strings.ToLower(value)
		var knownHostsPath string
		if idx := strings.Index(lowerValue, "userknownhostsfile="); idx != -1 {
			rest := value[idx+len("userknownhostsfile="):]
			knownHostsPath = strings.Fields(rest)[0]
		} else if idx := strings.Index(lowerValue, "userknownhostsfile "); idx != -1 {
			rest := value[idx+len("userknownhostsfile "):]
			knownHostsPath = strings.Fields(rest)[0]
		}
		if knownHostsPath != "" && IsNullDevice(knownHostsPath) {
			findings = append(findings, models.Finding{
				ID:       "git-ssh-no-known-hosts",
				Probe:    p.Name(),
				Severity: "high",
				Title:    "Git SSH Known Hosts Disabled",
				Message:  "Git is configured to ignore the SSH known_hosts file, preventing host key verification.",
				Path:     "git-config:core.sshcommand",
				Metadata: map[string]interface{}{
					"config_key":   "core.sshcommand",
					"config_value": value,
				},
			})
		}
	}

	return findings
}

// checkCredentialStorage checks for insecure credential storage
func (p *GitProbe) checkCredentialStorage(config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["credential.helper"]; ok {
		lowerValue := strings.ToLower(value)

		// Check for plaintext storage
		if strings.Contains(lowerValue, "store") && !strings.Contains(lowerValue, "cache") {
			// Get platform-appropriate path for the message
			credPath := "~/.git-credentials"
			if home, err := os.UserHomeDir(); err == nil {
				credPath = filepath.Join(home, ".git-credentials")
			}
			findings = append(findings, models.Finding{
				ID:       "git-credential-plaintext",
				Probe:    p.Name(),
				Severity: "high",
				Title:    "Git Credentials Stored in Plaintext",
				Message:  "Git is configured to store credentials in plaintext on disk (" + credPath + "). These credentials can be easily accessed by any process or user with filesystem access.",
				Path:     "git-config:credential.helper",
				Metadata: map[string]interface{}{
					"config_key":   "credential.helper",
					"config_value": value,
				},
			})
		}
	}

	return findings
}

// checkProtocolSettings checks for insecure protocol configurations
func (p *GitProbe) checkProtocolSettings(config map[string]string) []models.Finding {
	var findings []models.Finding

	dangerousProtocols := []string{"ext", "fd", "file"}

	for key, value := range config {
		if strings.HasPrefix(key, "protocol.") && strings.HasSuffix(key, ".allow") {
			protocol := strings.TrimSuffix(strings.TrimPrefix(key, "protocol."), ".allow")

			if strings.ToLower(value) == "always" {
				for _, dangerous := range dangerousProtocols {
					if strings.ToLower(protocol) == dangerous {
						findings = append(findings, models.Finding{
							ID:       "git-dangerous-protocol",
							Probe:    p.Name(),
							Severity: "medium",
							Title:    "Git Dangerous Protocol Enabled",
							Message:  "Git is configured to always allow the '" + protocol + "' protocol, which can be used to execute arbitrary commands or access local files.",
							Path:     "git-config:" + key,
							Metadata: map[string]interface{}{
								"config_key":   key,
								"config_value": value,
								"protocol":     protocol,
							},
						})
					}
				}
			}
		}
	}

	return findings
}

// checkFsckSettings checks for disabled object verification
func (p *GitProbe) checkFsckSettings(config map[string]string) []models.Finding {
	var findings []models.Finding

	fsckKeys := []string{"transfer.fsckobjects", "fetch.fsckobjects", "receive.fsckobjects"}

	for _, key := range fsckKeys {
		if value, ok := config[key]; ok && strings.ToLower(value) == "false" {
			findings = append(findings, models.Finding{
				ID:       "git-fsck-disabled",
				Probe:    p.Name(),
				Severity: "medium",
				Title:    "Git Object Verification Disabled",
				Message:  "Git is configured to skip object verification (" + key + "=false). This could allow corrupted or malicious objects to be accepted.",
				Path:     "git-config:" + key,
				Metadata: map[string]interface{}{
					"config_key":   key,
					"config_value": value,
				},
			})
		}
	}

	return findings
}

// checkProxySettings checks for potentially malicious proxy configurations
func (p *GitProbe) checkProxySettings(config map[string]string) []models.Finding {
	var findings []models.Finding

	proxyKeys := []string{"http.proxy", "https.proxy", "core.gitproxy"}

	for _, key := range proxyKeys {
		if value, ok := config[key]; ok && value != "" {
			findings = append(findings, models.Finding{
				ID:       "git-proxy-configured",
				Probe:    p.Name(),
				Severity: "low",
				Title:    "Git Proxy Configured",
				Message:  "Git is configured to use a proxy (" + key + "). Ensure this proxy is trusted, as it can intercept all Git traffic.",
				Path:     "git-config:" + key,
				Metadata: map[string]interface{}{
					"config_key":   key,
					"config_value": value,
				},
			})
		}
	}

	return findings
}

// checkHooksPath checks for custom git hooks path
func (p *GitProbe) checkHooksPath(config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["core.hookspath"]; ok && value != "" {
		findings = append(findings, models.Finding{
			ID:       "git-custom-hooks-path",
			Probe:    p.Name(),
			Severity: "medium",
			Title:    "Custom Git Hooks Path Configured",
			Message:  "Git is configured to use a custom hooks directory. This could be used to execute malicious code during Git operations.",
			Path:     "git-config:core.hookspath",
			Metadata: map[string]interface{}{
				"config_key":   "core.hookspath",
				"config_value": value,
			},
		})
	}

	return findings
}

// scanGitConfigForSecrets scans git config values for embedded secrets
func (p *GitProbe) scanGitConfigForSecrets(config map[string]string) []models.Finding {
	findings := make([]models.Finding, 0, len(config))

	for configKey, configValue := range config {
		// Run detectors on config values
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "git-config:" + configKey,
			ProbeName: p.Name(),
		})
		detectedSecrets := p.detectorRegistry.DetectAll(configValue, detCtx)
		findings = append(findings, detectedSecrets...)
	}

	return findings
}
