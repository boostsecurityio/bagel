// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// HTTPAuthDetector detects HTTP authentication credentials in various contexts
type HTTPAuthDetector struct {
	authPatterns   map[string]*tokenPattern
	redactPatterns []RedactPattern
}

// NewHTTPAuthDetector creates a new HTTP authentication detector
func NewHTTPAuthDetector() *HTTPAuthDetector {
	return &HTTPAuthDetector{
		// Redaction patterns: Bearer+JWT before Bearer+generic, URL auth
		redactPatterns: []RedactPattern{
			{
				Regex: regexp.MustCompile(
					`Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
				Replacement: `Bearer [REDACTED-jwt]`,
				Label:       "REDACTED-jwt",
				Prefixes:    []string{"Bearer"},
			},
			{
				Regex: regexp.MustCompile(
					`Bearer\s+[A-Za-z0-9_.\-/+=]{20,}`),
				Replacement: `Bearer [REDACTED-bearer-token]`,
				Label:       "REDACTED-bearer-token",
				Prefixes:    []string{"Bearer"},
			},
			{
				Regex: regexp.MustCompile(
					`Basic\s+[A-Za-z0-9+/=]{20,}`),
				Replacement: `Basic [REDACTED-basic-auth]`,
				Label:       "REDACTED-basic-auth",
				Prefixes:    []string{"Basic"},
			},
			{
				Regex:       regexp.MustCompile(`(https?://)[^:"\s\\]+:[^@"\s\\]+(@)`),
				Replacement: `${1}[REDACTED-basic-auth]${2}`,
				Label:       "REDACTED-basic-auth",
				Prefixes:    []string{"://"},
			},
			{
				Regex: regexp.MustCompile(
					`(?:X-API-Key|x-api-key|Authorization)[":\s]+[A-Za-z0-9_.\-/+=]{30,}`),
				Replacement: `[REDACTED-api-key-header]`,
				Label:       "REDACTED-api-key-header",
				Prefixes:    []string{"X-API-Key", "x-api-key", "Authorization"},
			},
		},
		authPatterns: map[string]*tokenPattern{
			"bearer-token": {
				// Matches: Authorization: Bearer <token>
				// Also matches: Authorization: Token <token> and Authorization: Api-Token <token>
				regex:       regexp.MustCompile(`(?i)\bAuthorization:\s*(?:Bearer|(?:Api-)?Token)\s+([\w=~@.+/-]{16,})\b`),
				tokenType:   "bearer-token",
				description: "Bearer Token in Authorization Header",
			},
			"basic-auth": {
				// Matches: Authorization: Basic <base64>
				regex:       regexp.MustCompile(`(?i)\bAuthorization:\s*Basic\s+([a-zA-Z0-9+/]{16,}={0,2})\b`),
				tokenType:   "basic-auth",
				description: "Basic Authentication in Authorization Header",
			},
			"api-key-header": {
				// Matches various API key header formats:
				// X-API-Key:, X-Api-Key:, API-Key:, Api-Key:, X-Auth-Token:, etc.
				regex:       regexp.MustCompile(`(?i)\b(?:X-)?(?:API|Api)-?(?:Key|Token):\s*([\w=~@.+/-]{16,})\b`),
				tokenType:   "api-key-header",
				description: "API Key in Header",
			},
			"basic-auth-url": {
				// Matches: username:password@ in URLs (http://user:pass@host)
				regex:       regexp.MustCompile(`(?i)\b(?:https?|ftp)://([a-zA-Z0-9_.-]{3,}):([^@\s]{3,})@`),
				tokenType:   "basic-auth-url",
				description: "Basic Authentication in URL",
			},
		},
	}
}

// Name returns the detector name
func (d *HTTPAuthDetector) Name() string {
	return "http-authentication"
}

// Detect scans content for HTTP authentication credentials and returns findings
func (d *HTTPAuthDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	// Check for all authentication patterns
	for _, pattern := range d.authPatterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				// Extract the credential from the capture group
				credential := match[1]
				findings = append(findings, d.createFinding(credential, pattern, ctx))
			}
		}
	}

	return findings
}

// Redact replaces HTTP auth credentials in content with redaction markers.
func (d *HTTPAuthDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for detected HTTP authentication credentials
func (d *HTTPAuthDetector) createFinding(credential string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	return models.Finding{
		ID:          "http-auth-" + pattern.tokenType,
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(credential, ctx.FingerprintSalt),
		Severity:    "critical",
		Title:       fmt.Sprintf("HTTP Authentication Credential Detected (%s)", pattern.description),
		Message: fmt.Sprintf(
			"A %s was detected in %s. "+
				"HTTP authentication credentials in plain text may be exposed in logs, shell history, "+
				"configuration files, or source code. This could allow unauthorized access to protected resources. "+
				"Use environment variables, secure credential storage, or secret management systems instead.",
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
