// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// GenericAPIKeyDetector detects generic API keys and high-entropy secrets
type GenericAPIKeyDetector struct {
	regex           *regexp.Regexp
	minEntropy      float64
	excludePatterns []*regexp.Regexp
	redactPatterns  []RedactPattern
}

// NewGenericAPIKeyDetector creates a new generic API key detector
func NewGenericAPIKeyDetector() *GenericAPIKeyDetector {
	pattern := `(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`

	return &GenericAPIKeyDetector{
		regex:          regexp.MustCompile(pattern),
		minEntropy:     3.5,
		redactPatterns: nil, // Header-based API key redaction is handled by HTTPAuthDetector
		excludePatterns: []*regexp.Regexp{
			// Exclude common placeholders and examples
			regexp.MustCompile(`(?i)^(your|my|the|example|sample|test|demo|placeholder|change|replace|insert|put)[-_]`),
			regexp.MustCompile(`(?i)(your|my|the|example|sample|test|demo|placeholder|change|replace|insert|put)[-_](key|token|secret|password|api|auth)`),
			regexp.MustCompile(`(?i)^(xxx|yyy|zzz|abc|123)`),
			regexp.MustCompile(`(?i)^[x]{5,}$`),
			regexp.MustCompile(`(?i)^[*]{5,}$`),
			regexp.MustCompile(`(?i)^\.{3,}$`),
			// Exclude environment variable references
			regexp.MustCompile(`^\$\{?[A-Z_]+\}?$`),
			// Exclude common non-secrets
			regexp.MustCompile(`(?i)^(true|false|null|none|undefined|localhost|127\.0\.0\.1)$`),
		},
	}
}

// Name returns the detector name
func (d *GenericAPIKeyDetector) Name() string {
	return "generic-api-key"
}

// Detect scans content for generic API keys and returns findings
func (d *GenericAPIKeyDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	matches := d.regex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		secret := match[1]

		// Skip if secret matches exclusion patterns
		if d.shouldExclude(secret) {
			continue
		}

		// Calculate Shannon entropy
		entropy := d.calculateEntropy(secret)

		// Only report if entropy meets threshold
		if entropy >= d.minEntropy {
			findings = append(findings, d.createFinding(secret, entropy, ctx))
		}
	}

	return findings
}

// shouldExclude checks if a value should be excluded from detection
func (d *GenericAPIKeyDetector) shouldExclude(value string) bool {
	trimmed := strings.TrimSpace(value)

	// Skip very short values
	if len(trimmed) < 10 {
		return true
	}

	// Check against exclusion patterns
	for _, pattern := range d.excludePatterns {
		if pattern.MatchString(trimmed) {
			return true
		}
	}

	return false
}

// calculateEntropy calculates Shannon entropy for a string
func (d *GenericAPIKeyDetector) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate Shannon entropy
	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// Redact replaces generic API keys in content with redaction markers.
func (d *GenericAPIKeyDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for a detected generic API key
func (d *GenericAPIKeyDetector) createFinding(secret string, entropy float64, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:          "generic-api-key",
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(secret, ctx.FingerprintSalt),
		Severity:    "high",
		Title:       "Generic API Key Detected",
		Description: "Generic API keys and high-entropy secrets can lead to unauthorized access if exposed.",
		Message:     fmt.Sprintf("A high-entropy secret was detected in %s (entropy: %.2f).", ctx.FormatSource(), entropy),
		Path:        ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    "generic-api-key",
			"entropy":       fmt.Sprintf("%.2f", entropy),
			"description":   "Generic API Key or High-Entropy Secret",
		},
	}
}
