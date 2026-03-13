// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// GitHubTokenDetector detects various GitHub token types
type GitHubTokenDetector struct {
	tokenPatterns  map[string]*tokenPattern
	redactPatterns []RedactPattern
}

type tokenPattern struct {
	regex       *regexp.Regexp
	tokenType   string
	description string
}

// NewGitHubPATDetector creates a new GitHub token detector
func NewGitHubPATDetector() *GitHubTokenDetector {
	return &GitHubTokenDetector{
		tokenPatterns: map[string]*tokenPattern{
			"ghp": {
				regex:       regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
				tokenType:   "classic-pat",
				description: "Classic Personal Access Token",
			},
			"github_pat": {
				regex:       regexp.MustCompile(`github_pat_\w{82}`),
				tokenType:   "fine-grained-pat",
				description: "Fine-grained Personal Access Token",
			},
			"gho": {
				regex:       regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
				tokenType:   "oauth-token",
				description: "OAuth Access Token",
			},
			"ghu": {
				regex:       regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`),
				tokenType:   "app-user-token",
				description: "GitHub App User-to-Server Token",
			},
			"ghs": {
				regex:       regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),
				tokenType:   "app-server-token",
				description: "GitHub App Server-to-Server Token",
			},
			"ghr": {
				regex:       regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`),
				tokenType:   "refresh-token",
				description: "GitHub Refresh Token",
			},
		},
		redactPatterns: []RedactPattern{
			{
				Regex:       regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,}`),
				Replacement: `[REDACTED-github-pat]`,
				Label:       "REDACTED-github-pat",
				Prefixes:    []string{"ghp_"},
			},
			{
				Regex:       regexp.MustCompile(`gho_[A-Za-z0-9_]{36,}`),
				Replacement: `[REDACTED-github-oauth]`,
				Label:       "REDACTED-github-oauth",
				Prefixes:    []string{"gho_"},
			},
			{
				Regex:       regexp.MustCompile(`ghu_[A-Za-z0-9_]{36,}`),
				Replacement: `[REDACTED-github-user]`,
				Label:       "REDACTED-github-user",
				Prefixes:    []string{"ghu_"},
			},
			{
				Regex:       regexp.MustCompile(`ghs_[A-Za-z0-9_]{36,}`),
				Replacement: `[REDACTED-github-app]`,
				Label:       "REDACTED-github-app",
				Prefixes:    []string{"ghs_"},
			},
			{
				Regex:       regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
				Replacement: `[REDACTED-github-fine-pat]`,
				Label:       "REDACTED-github-fine-pat",
				Prefixes:    []string{"github_pat_"},
			},
		},
	}
}

// Name returns the detector name
func (d *GitHubTokenDetector) Name() string {
	return "github-token"
}

// Detect scans content for GitHub tokens and returns findings
func (d *GitHubTokenDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	// Check for all token types
	for _, pattern := range d.tokenPatterns {
		matches := pattern.regex.FindAllString(content, -1)
		for _, match := range matches {
			findings = append(findings, d.createFinding(match, pattern, ctx))
		}
	}

	return findings
}

// Redact replaces GitHub tokens in content with redaction markers.
func (d *GitHubTokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for a detected GitHub token
func (d *GitHubTokenDetector) createFinding(token string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:          "github-token-" + pattern.tokenType,
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(token, ctx.FingerprintSalt),
		Severity:    "critical",
		Title:       fmt.Sprintf("GitHub Token Detected (%s)", pattern.description),
		Message: fmt.Sprintf(
			"A GitHub %s was detected in %s. "+
				"This credential provides access to your GitHub account and/or repositories. ",
			pattern.description,
			ctx.FormatSource(),
		),
		Path: ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
		},
	}
}
