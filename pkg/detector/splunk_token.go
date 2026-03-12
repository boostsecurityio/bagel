// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// SplunkTokenDetector detects Splunk session tokens
type SplunkTokenDetector struct {
	tokenPattern   *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewSplunkTokenDetector creates a new Splunk session token detector
func NewSplunkTokenDetector() *SplunkTokenDetector {
	pattern := regexp.MustCompile(`\b(splunkd_[A-Za-z0-9]{32,})\b`)
	return &SplunkTokenDetector{
		tokenPattern: pattern,
		redactPatterns: []RedactPattern{
			{
				Regex:       pattern,
				Replacement: `[REDACTED-splunk-session]`,
				Label:       "REDACTED-splunk-session",
				Prefixes:    []string{"splunkd_"},
			},
		},
	}
}

// Name returns the detector name
func (d *SplunkTokenDetector) Name() string {
	return "splunk-token"
}

// Detect scans content for Splunk session tokens and returns findings
func (d *SplunkTokenDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	matches := d.tokenPattern.FindAllString(content, -1)
	findings := make([]models.Finding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, models.Finding{
			ID:          "splunk-session-token",
			Fingerprint: models.SaltedFingerprint(match, ctx.FingerprintSalt),
			Severity:    "critical",
			Title:       "Splunk Session Token Detected",
			Message: fmt.Sprintf(
				"A Splunk session token was detected in %s. "+
					"This credential provides authenticated access to Splunk. "+
					"Revoke the session and rotate credentials.",
				ctx.FormatSource(),
			),
			Path: ctx.Source,
			Metadata: map[string]interface{}{
				"detector_name": d.Name(),
				"token_type":    "splunk-session-token",
			},
		})
	}
	return findings
}

// Redact replaces Splunk session tokens in content with redaction markers.
func (d *SplunkTokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
