// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// SSHProbe checks SSH configuration and key security
type SSHProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewSSHProbe creates a new SSH probe
func NewSSHProbe(config models.ProbeSettings, registry *detector.Registry) *SSHProbe {
	return &SSHProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *SSHProbe) Name() string {
	return "ssh"
}

// IsEnabled returns whether the probe is enabled
func (p *SSHProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *SSHProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *SSHProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the SSH probe
func (p *SSHProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping SSH probe")
		return findings, nil
	}

	// Get SSH config files from file index
	sshConfigs := p.fileIndex.Get("ssh_config")
	sshKeys := p.fileIndex.Get("ssh_keys")

	log.Ctx(ctx).Debug().
		Int("config_count", len(sshConfigs)).
		Int("keys_count", len(sshKeys)).
		Msg("Found SSH files")

	// Process SSH config files
	for _, configPath := range sshConfigs {
		configFindings := p.processSSHConfig(ctx, configPath)
		findings = append(findings, configFindings...)
	}

	// Process SSH private keys
	for _, keyPath := range sshKeys {
		keyFindings := p.processSSHKey(ctx, keyPath)
		findings = append(findings, keyFindings...)
	}

	return findings, nil
}

// processSSHConfig reads and analyzes an SSH config file
func (p *SSHProbe) processSSHConfig(ctx context.Context, configPath string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

	// Read config file
	content, err := os.ReadFile(configPath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", configPath).
			Msg("Cannot read SSH config file")
		return findings
	}

	contentStr := string(content)

	// Check SSH config settings
	// We scan line-by-line to catch insecure settings in ANY Host block,
	// not just the last one encountered
	findings = append(findings, p.checkSSHConfigContent(configPath, contentStr)...)

	return findings
}

// processSSHKey reads and analyzes an SSH private key file
func (p *SSHProbe) processSSHKey(ctx context.Context, keyPath string) []models.Finding {
	var findings []models.Finding

	// Skip public keys (*.pub files)
	if strings.HasSuffix(keyPath, ".pub") {
		return findings
	}

	// Check file permissions
	findings = append(findings, p.checkKeyPermissions(ctx, keyPath)...)

	// Read key file
	content, err := os.ReadFile(keyPath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", keyPath).
			Msg("Cannot read SSH key file")
		return findings
	}

	contentStr := string(content)

	// Use detector to check if key is encrypted
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + keyPath,
		ProbeName: p.Name(),
	})
	detectedKeys := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedKeys...)

	return findings
}

// checkSSHConfigContent scans SSH config content line-by-line to detect insecure settings
func (p *SSHProbe) checkSSHConfigContent(filePath string, content string) []models.Finding {
	var findings []models.Finding
	lines := strings.Split(content, "\n")

	// Track which insecure settings we've already reported to avoid duplicates
	reportedIssues := make(map[string]bool)
	currentHost := "*" // Default/global scope

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key value pairs (space or tab separated)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.Join(parts[1:], " ")

		// Track Host blocks for context
		if key == "host" {
			currentHost = value
			continue
		}

		// Check for StrictHostKeyChecking disabled
		if key == "stricthostkeychecking" && strings.ToLower(value) == "no" {
			issueKey := "stricthostkeychecking-" + currentHost
			if !reportedIssues[issueKey] {
				findings = append(findings, models.Finding{
					ID:          "ssh-strict-host-key-checking-disabled",
					Type:        models.FindingTypeMisconfiguration,
					Fingerprint: models.FingerprintFromFields("ssh-strict-host-key-checking-disabled", filePath, currentHost),
					Probe:       p.Name(),
					Severity:    "high",
					Title:       "SSH StrictHostKeyChecking Disabled",
					Message: fmt.Sprintf(
						"SSH config disables host key verification (StrictHostKeyChecking=no) for host pattern '%s' at line %d. "+
							"This makes you vulnerable to man-in-the-middle attacks. "+
							"Remove this setting or set it to 'yes' or 'ask'.",
						currentHost,
						lineNum+1,
					),
					Path: filePath,
					Metadata: map[string]interface{}{
						"config_key":   "StrictHostKeyChecking",
						"config_value": value,
						"host_pattern": currentHost,
						"line_number":  lineNum + 1,
					},
				})
				reportedIssues[issueKey] = true
			}
		}

		// Check for UserKnownHostsFile disabled (/dev/null, nul, etc.)
		// Use cross-platform null device check
		if key == "userknownhostsfile" && IsNullDevice(value) {
			issueKey := "userknownhostsfile-" + currentHost
			if !reportedIssues[issueKey] {
				findings = append(findings, models.Finding{
					ID:          "ssh-known-hosts-disabled",
					Type:        models.FindingTypeMisconfiguration,
					Fingerprint: models.FingerprintFromFields("ssh-known-hosts-disabled", filePath, currentHost),
					Probe:       p.Name(),
					Severity:    "high",
					Title:       "SSH Known Hosts File Disabled",
					Message: fmt.Sprintf(
						"SSH config disables host key verification (UserKnownHostsFile=%s) for host pattern '%s' at line %d. "+
							"This makes you vulnerable to man-in-the-middle attacks. "+
							"Use the default known_hosts file or specify a valid path.",
						value,
						currentHost,
						lineNum+1,
					),
					Path: filePath,
					Metadata: map[string]interface{}{
						"config_key":   "UserKnownHostsFile",
						"config_value": value,
						"host_pattern": currentHost,
						"line_number":  lineNum + 1,
					},
				})
				reportedIssues[issueKey] = true
			}
		}

		// Check for ForwardAgent enabled
		if key == "forwardagent" && strings.ToLower(value) == "yes" {
			issueKey := "forwardagent-" + currentHost
			if !reportedIssues[issueKey] {
				severity := "medium"
				message := fmt.Sprintf(
					"SSH agent forwarding is enabled (ForwardAgent=yes) for host pattern '%s' at line %d. "+
						"This can be a security risk if you connect to untrusted hosts, "+
						"as they could use your forwarded keys.",
					currentHost,
					lineNum+1,
				)

				// Global wildcard is more severe
				if currentHost == "*" {
					message = fmt.Sprintf(
						"SSH agent forwarding is enabled globally (ForwardAgent=yes) at line %d. "+
							"This can be a security risk if you connect to untrusted hosts, "+
							"as they could use your forwarded keys. "+
							"Consider enabling it only for specific trusted hosts.",
						lineNum+1,
					)
				}

				findings = append(findings, models.Finding{
					ID:          "ssh-forward-agent-enabled",
					Type:        models.FindingTypeMisconfiguration,
					Fingerprint: models.FingerprintFromFields("ssh-forward-agent-enabled", filePath, currentHost),
					Probe:       p.Name(),
					Severity:    severity,
					Title:       "SSH Agent Forwarding Enabled",
					Message:     message,
					Path:        filePath,
					Metadata: map[string]interface{}{
						"config_key":   "ForwardAgent",
						"config_value": value,
						"host_pattern": currentHost,
						"line_number":  lineNum + 1,
					},
				})
				reportedIssues[issueKey] = true
			}
		}
	}

	return findings
}

// checkKeyPermissions checks SSH private key file permissions
func (p *SSHProbe) checkKeyPermissions(ctx context.Context, keyPath string) []models.Finding {
	var findings []models.Finding

	// Skip Unix permission checks on Windows - Windows uses ACLs instead of Unix permission bits
	if runtime.GOOS == "windows" {
		log.Ctx(ctx).Debug().
			Str("file", keyPath).
			Msg("Skipping Unix permission check on Windows")
		return findings
	}

	fileInfo, err := os.Stat(keyPath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", keyPath).
			Msg("Cannot stat SSH key file")
		return findings
	}

	// Check permissions (should be 0600 or 0400)
	mode := fileInfo.Mode().Perm()
	if mode&0077 != 0 { // Check if group or other have any permissions
		findings = append(findings, models.Finding{
			ID:          "ssh-key-insecure-permissions",
			Type:        models.FindingTypeMisconfiguration,
			Fingerprint: models.FingerprintFromFields("ssh-key-insecure-permissions", keyPath),
			Probe:       p.Name(),
			Severity:    "high",
			Title:       "SSH Private Key Has Insecure Permissions",
			Message: "SSH private key " + filepath.Base(keyPath) + " has insecure file permissions (" +
				mode.String() + "). " +
				"Private keys should only be readable by the owner (permissions 0600 or 0400). " +
				GetPermissionFixMessage(keyPath),
			Path: keyPath,
			Metadata: map[string]interface{}{
				"current_permissions":  mode.String(),
				"expected_permissions": "0600",
			},
		})
	}

	return findings
}
