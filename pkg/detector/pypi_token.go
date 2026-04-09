// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// PyPITokenDetector detects PyPI API tokens
type PyPITokenDetector struct {
	tokenPattern   *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewPyPITokenDetector creates a new PyPI API token detector
func NewPyPITokenDetector() *PyPITokenDetector {
	pattern := regexp.MustCompile(`\b(pypi-[A-Za-z0-9_-]{16,})\b`)
	return &PyPITokenDetector{
		tokenPattern: pattern,
		redactPatterns: []RedactPattern{
			{
				Regex:       pattern,
				Replacement: `[REDACTED-pypi-token]`,
				Label:       "REDACTED-pypi-token",
				Prefixes:    []string{"pypi-"},
			},
		},
	}
}

// Name returns the detector name
func (d *PyPITokenDetector) Name() string {
	return "pypi-token"
}

// Detect scans content for PyPI API tokens and returns findings
func (d *PyPITokenDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	matches := d.tokenPattern.FindAllString(content, -1)
	seen := make(map[string]bool)
	findings := make([]models.Finding, 0, len(matches))

	for _, match := range matches {
		if seen[match] {
			continue
		}
		seen[match] = true

		findings = append(findings, models.Finding{
			ID:          "pypi-api-token",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.SaltedFingerprint(match, ctx.FingerprintSalt),
			Severity:    "critical",
			Title:       "PyPI API Token Detected",
			Description: "A PyPI API token was found. PyPI tokens allow publishing and managing Python packages.",
			Message:     fmt.Sprintf("A PyPI API token was detected in %s.", ctx.FormatSource()),
			Path:        ctx.Source,
			Metadata: map[string]interface{}{
				"detector_name": d.Name(),
				"token_type":    "pypi-api-token",
			},
		})
	}

	return findings
}

// Redact replaces PyPI tokens in content with redaction markers.
func (d *PyPITokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
