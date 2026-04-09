// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// WireGuardKeyDetector detects WireGuard private keys in configuration files
type WireGuardKeyDetector struct {
	// keyPattern matches PrivateKey directives with base64-encoded Curve25519 keys (32 bytes = 44 base64 chars)
	keyPattern     *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewWireGuardKeyDetector creates a new WireGuard private key detector
func NewWireGuardKeyDetector() *WireGuardKeyDetector {
	keyPattern := regexp.MustCompile(`PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)`)
	redactPattern := regexp.MustCompile(`(PrivateKey\s*=\s*)[A-Za-z0-9+/]{43}=`)

	return &WireGuardKeyDetector{
		keyPattern: keyPattern,
		redactPatterns: []RedactPattern{
			{
				Regex:       redactPattern,
				Replacement: `${1}[REDACTED-wireguard-key]`,
				Label:       "REDACTED-wireguard-key",
				Prefixes:    []string{"PrivateKey"},
			},
		},
	}
}

// Name returns the detector name
func (d *WireGuardKeyDetector) Name() string {
	return "wireguard-key"
}

// Detect scans content for WireGuard private keys and returns findings
func (d *WireGuardKeyDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	matches := d.keyPattern.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	findings := make([]models.Finding, 0, len(matches))

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		key := match[1]
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, models.Finding{
			ID:          "wireguard-private-key",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.SaltedFingerprint(key, ctx.FingerprintSalt),
			Severity:    "critical",
			Title:       "WireGuard Private Key Detected",
			Description: "A WireGuard private key was found. " +
				"WireGuard private keys grant VPN access to protected networks.",
			Message: fmt.Sprintf("A WireGuard private key was detected in %s.", ctx.FormatSource()),
			Path:    ctx.Source,
			Metadata: map[string]interface{}{
				"detector_name": d.Name(),
				"token_type":    "wireguard-private-key",
			},
		})
	}

	return findings
}

// Redact replaces WireGuard private keys in content with redaction markers.
func (d *WireGuardKeyDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
