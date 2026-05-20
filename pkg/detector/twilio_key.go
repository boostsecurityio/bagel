// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// TwilioKeyDetector detects Twilio API Key SIDs.
//
// The SID itself (SK + 32 hex) is an identifier, not a secret. The
// paired auth token (32 hex chars, no fixed prefix) is the actual
// credential — but a bare 32-hex string is too ambiguous to detect
// directly without producing huge volumes of false positives. By
// surfacing the SID we give the user a strong starting point: the
// matching token typically lives in the same file or env block.
//
// We deliberately skip Account SIDs (AC + 32 hex). They identify the
// account but, like the API Key SID, aren't secrets; reporting both
// just doubles the noise without adding signal.
type TwilioKeyDetector struct {
	pattern        *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewTwilioKeyDetector creates a new Twilio API Key SID detector.
func NewTwilioKeyDetector() *TwilioKeyDetector {
	pattern := regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`)
	return &TwilioKeyDetector{
		pattern: pattern,
		redactPatterns: []RedactPattern{
			{
				Regex:       pattern,
				Replacement: `[REDACTED-twilio-api-key-sid]`,
				Label:       "REDACTED-twilio-api-key-sid",
				Prefixes:    []string{"SK"},
			},
		},
	}
}

// Name returns the detector name.
func (d *TwilioKeyDetector) Name() string {
	return "twilio-key"
}

// Detect scans content for Twilio API Key SIDs and returns findings.
func (d *TwilioKeyDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	matches := d.pattern.FindAllString(content, -1)
	findings := make([]models.Finding, 0, len(matches))
	seen := make(map[string]bool, len(matches))

	for _, sid := range matches {
		if seen[sid] {
			continue
		}
		seen[sid] = true

		findings = append(findings, models.Finding{
			ID:          "twilio-api-key-sid",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.SaltedFingerprint(sid, ctx.FingerprintSalt),
			// Medium because the SID alone can't authenticate — but
			// its presence almost always means the paired auth token
			// is nearby, which IS the real secret.
			Severity: "medium",
			Title:    "Twilio API Key SID Detected",
			Description: "A Twilio API Key SID identifies a Twilio API Key but is not itself a secret. " +
				"The paired auth token (32 hex characters, typically named TWILIO_AUTH_TOKEN or stored " +
				"next to the SID) is the actual credential — search the same file/environment for it " +
				"and rotate it from the Twilio console.",
			Message: fmt.Sprintf("A Twilio API Key SID was detected in %s.", ctx.FormatSource()),
			Path:    ctx.Source,
			Metadata: map[string]interface{}{
				"detector_name": d.Name(),
				"token_type":    "twilio-api-key-sid",
			},
		})
	}
	return findings
}

// Redact replaces Twilio SIDs in content with a redaction marker.
func (d *TwilioKeyDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
