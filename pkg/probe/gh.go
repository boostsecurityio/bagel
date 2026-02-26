// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os/exec"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// GHProbe checks for GitHub CLI authentication
type GHProbe struct {
	enabled bool
	config  models.ProbeSettings
}

// NewGHProbe creates a new GitHub CLI probe
func NewGHProbe(config models.ProbeSettings) *GHProbe {
	return &GHProbe{
		enabled: config.Enabled,
		config:  config,
	}
}

// Name returns the probe name
func (p *GHProbe) Name() string {
	return "gh"
}

// IsEnabled returns whether the probe is enabled
func (p *GHProbe) IsEnabled() bool {
	return p.enabled
}

// Execute runs the GitHub CLI probe
func (p *GHProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	findings := make([]models.Finding, 0, 1)

	// Check if gh CLI is installed
	ghPath, err := exec.LookPath("gh")
	if err != nil {
		log.Ctx(ctx).Debug().
			Msg("GitHub CLI (gh) not found in PATH, skipping probe")
		return findings, nil
	}

	log.Ctx(ctx).Debug().
		Str("gh_path", ghPath).
		Msg("Found GitHub CLI")

	// Try to get the auth token status
	// We run "gh auth token" which returns exit code 0 if authenticated
	// The actual token is written to stdout, but we discard it immediately
	cmd := exec.CommandContext(ctx, "gh", "auth", "token")

	// Run the command - we only care about the exit code
	// The token value is intentionally discarded and never stored
	err = cmd.Run()
	if err != nil {
		// Command failed - either not authenticated or some other error
		// This is expected when gh is not authenticated
		log.Ctx(ctx).Debug().
			Err(err).
			Msg("GitHub CLI not authenticated or command failed")
		return findings, nil
	}

	// If we get here, gh auth token succeeded - there's an active session
	findings = append(findings, models.Finding{
		ID:       "gh-auth-token-present",
		Probe:    p.Name(),
		Severity: "medium",
		Title:    "GitHub CLI Authentication Detected",
		Message: "The GitHub CLI (gh) has an active authenticated session on this machine. " +
			"If this machine is compromised, an attacker could use the gh CLI to access your GitHub account, " +
			"repositories, and organization resources without needing to know your credentials. " +
			"Consider using 'gh auth logout' when not actively using the CLI, or ensure this machine has appropriate security controls.",
		Path: ghPath,
		Metadata: map[string]interface{}{
			"gh_path": ghPath,
		},
	})

	return findings, nil
}
