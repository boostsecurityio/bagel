// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os/exec"
	"runtime"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// GHProbe checks for GitHub CLI authentication
type GHProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
}

// NewGHProbe creates a new GitHub CLI probe
func NewGHProbe(config models.ProbeSettings, registry *detector.Registry) *GHProbe {
	return &GHProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *GHProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
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
	ghAuthenticated := cmd.Run() == nil

	if ghAuthenticated {
		findings = append(findings, models.Finding{
			ID:          "gh-auth-token-present",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.FingerprintFromFields("gh-auth-token-present", ghPath),
			Probe:       p.Name(),
			Severity:    "medium",
			Title:       "GitHub CLI Authentication Detected",
			Description: "An active GitHub CLI session was found. " +
				"If this machine is compromised, the session token can be used to access your GitHub account, repositories, and organization resources.",
			Message: "GitHub CLI authenticated at " + ghPath,
			Path:    ghPath,
			Metadata: map[string]interface{}{
				"gh_path": ghPath,
			},
		})
	} else {
		log.Ctx(ctx).Debug().Msg("GitHub CLI not authenticated")
	}

	// On macOS, gh auth logout does not remove the OAuth token from the
	// macOS Keychain (https://github.com/cli/cli/issues/13111).
	// Check for leftover credentials regardless of gh auth status.
	if runtime.GOOS == "darwin" {
		findings = append(findings, p.checkKeychainLeftover(ctx, ghAuthenticated)...)
	}

	return findings, nil
}

// checkKeychainLeftover queries git credential-osxkeychain for a leftover
// github.com OAuth token that gh auth logout fails to remove.
func (p *GHProbe) checkKeychainLeftover(ctx context.Context, ghAuthenticated bool) []models.Finding {
	// If gh is authenticated, the keychain credential is expected -- skip.
	if ghAuthenticated {
		return nil
	}

	// Only relevant when git credential-osxkeychain is available
	credHelper := exec.CommandContext(ctx, "git", "credential-osxkeychain", "get")
	credHelper.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")

	output, err := credHelper.Output()
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Msg("No GitHub credential in macOS Keychain")
		return nil
	}

	// Extract the password value
	var password string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "password=") {
			password = strings.TrimPrefix(line, "password=")
			break
		}
	}

	if password == "" {
		return nil
	}

	// Run the password through the detector registry to confirm it's a known token type
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "osxkeychain:github.com",
		ProbeName: p.Name(),
	})
	findings := p.detectorRegistry.DetectAll(password, detCtx)

	if len(findings) == 0 {
		return nil
	}

	// Annotate each finding with keychain-specific context
	for i := range findings {
		findings[i].ID = "gh-keychain-leftover-" + findings[i].ID
		findings[i].Title = findings[i].Title + " (left in macOS Keychain after logout)"
		findings[i].Description = "gh auth logout does not remove the OAuth token from the macOS Keychain " +
			"(https://github.com/cli/cli/issues/13111). The token remains accessible via " +
			"git credential-osxkeychain and can be used to authenticate as you. " +
			"Remove it manually: printf 'protocol=https\\nhost=github.com\\n\\n' | git credential-osxkeychain erase"
		findings[i].Path = "osxkeychain:github.com"
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]interface{})
		}
		findings[i].Metadata["credential_helper"] = "osxkeychain"
		findings[i].Metadata["host"] = "github.com"
	}

	return findings
}
