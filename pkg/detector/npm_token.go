// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// NPMTokenDetector detects various NPM and Yarn authentication tokens
type NPMTokenDetector struct {
	tokenPatterns  map[string]*tokenPattern
	redactPatterns []RedactPattern
}

// NewNPMTokenDetector creates a new NPM token detector
func NewNPMTokenDetector() *NPMTokenDetector {
	return &NPMTokenDetector{
		tokenPatterns: map[string]*tokenPattern{
			"npm-auth-token": {
				regex:       regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "npm-auth-token",
				description: "NPM Authentication Token",
			},
		},
		redactPatterns: []RedactPattern{
			{
				Regex:       regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`),
				Replacement: `[REDACTED-npm-token]`,
				Label:       "REDACTED-npm-token",
				Prefixes:    []string{"npm_"},
			},
		},
	}
}

// Name returns the detector name
func (d *NPMTokenDetector) Name() string {
	return "npm-token"
}

// Detect scans content for NPM/Yarn tokens and returns findings
func (d *NPMTokenDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding
	matchedTokens := make(map[string]bool) // Track matched tokens to avoid duplicates

	for _, pattern := range d.tokenPatterns {
		matches := pattern.regex.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				// match[0], match[1] are the full match indices
				// match[2], match[3] are the captured token indices
				token := content[match[2]:match[3]]

				// Skip if this exact token was already matched by a more specific pattern
				if matchedTokens[token] {
					continue
				}

				matchedTokens[token] = true
				findings = append(findings, d.createFinding(token, pattern, ctx))
			}
		}
	}

	return findings
}

// Redact replaces NPM tokens in content with redaction markers.
func (d *NPMTokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for a detected NPM/Yarn token
func (d *NPMTokenDetector) createFinding(token string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:       "npm-token-" + pattern.tokenType,
		Severity: "critical",
		Title:    fmt.Sprintf("NPM Token Detected (%s)", pattern.description),
		Message: fmt.Sprintf(
			"An %s was detected in %s. "+
				"This credential provides access to NPM packages and registries. "+
				"Exposed tokens can allow unauthorized package publishing or access to private packages.",
			pattern.description,
			ctx.FormatSource(),
		),
		Path: ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
			"token_length":  len(token),
			"fingerprint":   Fingerprint(token),
		},
	}
}
