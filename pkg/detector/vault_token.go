// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// VaultTokenDetector detects HashiCorp Vault service tokens
type VaultTokenDetector struct {
	// hvsPattern matches current Vault service tokens (hvs. prefix)
	hvsPattern *regexp.Regexp
	// legacyPattern matches legacy Vault tokens (s. prefix)
	legacyPattern  *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewVaultTokenDetector creates a new HashiCorp Vault token detector
func NewVaultTokenDetector() *VaultTokenDetector {
	hvsPattern := regexp.MustCompile(`\bhvs\.[A-Za-z0-9]{24,}\b`)
	legacyPattern := regexp.MustCompile(`\bs\.[A-Za-z0-9]{24,}\b`)

	return &VaultTokenDetector{
		hvsPattern:    hvsPattern,
		legacyPattern: legacyPattern,
		redactPatterns: []RedactPattern{
			{
				Regex:       hvsPattern,
				Replacement: `[REDACTED-vault-token]`,
				Label:       "REDACTED-vault-token",
				Prefixes:    []string{"hvs."},
			},
			{
				Regex:       legacyPattern,
				Replacement: `[REDACTED-vault-token]`,
				Label:       "REDACTED-vault-token",
				Prefixes:    []string{"s."},
			},
		},
	}
}

// Name returns the detector name
func (d *VaultTokenDetector) Name() string {
	return "vault-token"
}

// Detect scans content for HashiCorp Vault tokens and returns findings
func (d *VaultTokenDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	var findings []models.Finding
	seen := make(map[string]bool)

	for _, pattern := range []*regexp.Regexp{d.hvsPattern, d.legacyPattern} {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true

			tokenType := "vault-service-token"
			if match[0] == 's' {
				tokenType = "vault-legacy-token"
			}

			findings = append(findings, models.Finding{
				ID:          tokenType,
				Type:        models.FindingTypeSecret,
				Fingerprint: models.SaltedFingerprint(match, ctx.FingerprintSalt),
				Severity:    "critical",
				Title:       "HashiCorp Vault Token Detected",
				Description: "A HashiCorp Vault token was found. " +
					"Vault tokens provide authenticated access to secrets stored in Vault.",
				Message: fmt.Sprintf("A Vault token was detected in %s.", ctx.FormatSource()),
				Path:    ctx.Source,
				Metadata: map[string]interface{}{
					"detector_name": d.Name(),
					"token_type":    tokenType,
				},
			})
		}
	}

	return findings
}

// Redact replaces Vault tokens in content with redaction markers.
func (d *VaultTokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
