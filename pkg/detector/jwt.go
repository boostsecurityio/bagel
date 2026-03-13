// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// JWTDetector detects JWT tokens in various contexts
type JWTDetector struct {
	tokenPatterns  map[string]*tokenPattern
	redactPatterns []RedactPattern
}

// NewJWTDetector creates a new JWT detector
func NewJWTDetector() *JWTDetector {
	return &JWTDetector{
		// Standalone JWT redaction (after Bearer patterns handled by HTTPAuthDetector)
		redactPatterns: []RedactPattern{
			{
				Regex: regexp.MustCompile(
					`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
				Replacement: `[REDACTED-jwt]`,
				Label:       "REDACTED-jwt",
				Prefixes:    []string{"eyJ"},
			},
		},
		tokenPatterns: map[string]*tokenPattern{
			"jwt-token": {
				// Matches: <base64_header>.<base64_payload>.<base64_sig>
				// The header is constrained with ey since any valid header should be a JSON object with at least one member (alg)
				// The same can't be said for the body (ex: {}), the signature also has no fixed format (binary data)
				regex:       regexp.MustCompile(`\b(ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)\b($|[^.])`),
				tokenType:   "jwt-token",
				description: "JWT Token",
			},
			"jwe-token": {
				// Matches: <base64_header>.<base64_enc_key>.<base64_iv>.<base64_ct>.<base64_tag>
				// The header is constrained with ey since any valid header should be a JSON object with at least one member (alg)
				// The same can't be said for any of the other sections
				regex:       regexp.MustCompile(`\b(ey[A-Za-z0-9-_]+(?:\.[A-Za-z0-9-_]+){4})\b`),
				tokenType:   "jwe-token",
				description: "JWE Token",
			},
		},
	}
}

// Name returns the detector name
func (d *JWTDetector) Name() string {
	return "jwt"
}

// Detect scans content for JWT tokens and returns findings
func (d *JWTDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	// Check for all token formats
	for _, pattern := range d.tokenPatterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				// Extract the token from the capture group
				credential := match[1]
				findings = append(findings, d.createFinding(credential, pattern, ctx))
			}
		}
	}

	return findings
}

// Redact replaces standalone JWT tokens in content with redaction markers.
func (d *JWTDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for detected JWT tokens
func (d *JWTDetector) createFinding(credential string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:          "jwt-" + pattern.tokenType,
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(credential, ctx.FingerprintSalt),
		Severity:    "critical",
		Title:       "JWT Token Detected",
		Description: "JWT tokens in plain text can be exposed in logs, shell history, or configuration files. " +
			"Use secure credential storage or secret management systems instead.",
		Message: fmt.Sprintf("A %s was detected in %s.", pattern.description, ctx.FormatSource()),
		Path:    ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
		},
	}
}
