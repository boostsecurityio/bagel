// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// AIServiceDetector detects API keys for various AI services
type AIServiceDetector struct {
	tokenPatterns map[string]*tokenPattern
}

// NewAIServiceDetector creates a new AI service API key detector
func NewAIServiceDetector() *AIServiceDetector {
	return &AIServiceDetector{
		tokenPatterns: map[string]*tokenPattern{
			"openai": {
				// Put hyphen at end of character class to avoid escaping issues
				regex:       regexp.MustCompile(`\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "openai-api-key",
				description: "OpenAI API Key",
			},
			"anthropic": {
				// Remove backslash before hyphen in character class
				regex:       regexp.MustCompile(`\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "anthropic-api-key",
				description: "Anthropic API Key",
			},
			"anthropic_admin": {
				// Remove backslash before hyphen in character class
				regex:       regexp.MustCompile(`\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "anthropic-admin-api-key",
				description: "Anthropic Admin API Key",
			},
			"huggingface": {
				regex:       regexp.MustCompile(`\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "huggingface-access-token",
				description: "Hugging Face Access Token",
			},
			"huggingface_org": {
				regex:       regexp.MustCompile(`\b(api_org_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`),
				tokenType:   "huggingface-org-token",
				description: "Hugging Face Organization API Token",
			},
		},
	}
}

// Name returns the detector name
func (d *AIServiceDetector) Name() string {
	return "ai-service"
}

// Detect scans content for AI service API keys and returns findings
func (d *AIServiceDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	// Check for all token types
	for _, pattern := range d.tokenPatterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				// Extract the actual token from the capture group
				findings = append(findings, d.createFinding(match[1], pattern, ctx))
			}
		}
	}

	return findings
}

// createFinding creates a finding for a detected AI service API key
func (d *AIServiceDetector) createFinding(token string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:       "ai-service-" + pattern.tokenType,
		Severity: "critical",
		Title:    fmt.Sprintf("AI Service API Key Detected (%s)", pattern.description),
		Message: fmt.Sprintf(
			"An %s was detected in %s. "+
				"This credential provides access to AI services and may incur costs or expose sensitive data. "+
				"Revoke this key immediately and rotate with a new one stored securely.",
			pattern.description,
			ctx.FormatSource(),
		),
		Path: ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
			"fingerprint":   Fingerprint(token),
		},
	}
}
