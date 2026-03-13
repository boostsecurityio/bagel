// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// CloudCredentialsDetector detects cloud provider credentials (AWS, GCP, Azure)
type CloudCredentialsDetector struct {
	credentialPatterns []*tokenPattern
	redactPatterns     []RedactPattern
}

// NewCloudCredentialsDetector creates a new cloud credentials detector
func NewCloudCredentialsDetector() *CloudCredentialsDetector {
	return &CloudCredentialsDetector{
		redactPatterns: []RedactPattern{
			{
				Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				Replacement: `[REDACTED-aws-access-key]`,
				Label:       "REDACTED-aws-access-key",
				Prefixes:    []string{"AKIA"},
			},
			{
				Regex:       regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
				Replacement: `[REDACTED-aws-sts-key]`,
				Label:       "REDACTED-aws-sts-key",
				Prefixes:    []string{"ASIA"},
			},
			{
				Regex: regexp.MustCompile(
					`((?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)["\s:=]+)[A-Za-z0-9+/=]{100,}`),
				Replacement: `${1}[REDACTED-aws-session-token]`,
				Label:       "REDACTED-aws-session-token",
				Prefixes:    []string{"aws_session_token", "AWS_SESSION_TOKEN", "SessionToken"},
			},
			{
				Regex:       regexp.MustCompile(`IQoJb3JpZ2lu[A-Za-z0-9+/=]{100,}`),
				Replacement: `[REDACTED-aws-session-token]`,
				Label:       "REDACTED-aws-session-token",
				Prefixes:    []string{"IQoJb3JpZ2lu"},
			},
			{
				Regex: regexp.MustCompile(
					`((?:aws_secret_access_key|secret_access_key|SecretAccessKey)["\s:=]+)[A-Za-z0-9+/]{40}`),
				Replacement: `${1}[REDACTED-aws-secret-key]`,
				Label:       "REDACTED-aws-secret-key",
				Prefixes:    []string{"aws_secret_access_key", "secret_access_key", "SecretAccessKey"},
			},
			{
				Regex: regexp.MustCompile(
					`((?:AccountKey|storage_key|StorageKey)["\s:=]+)[A-Za-z0-9+/]{86}==`),
				Replacement: `${1}[REDACTED-azure-storage-key]`,
				Label:       "REDACTED-azure-storage-key",
				Prefixes:    []string{"AccountKey", "storage_key", "StorageKey"},
			},
			{
				Regex:       regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
				Replacement: `[REDACTED-gcp-api-key]`,
				Label:       "REDACTED-gcp-api-key",
				Prefixes:    []string{"AIza"},
			},
		},
		// Patterns are checked in order - more specific patterns should come first
		credentialPatterns: []*tokenPattern{
			// Azure Credentials (check first - most specific due to length)
			{
				// Matches Azure Storage Account Key: 88 base64 characters followed by ==
				// Standalone format, not requiring key-value pair context
				regex:       regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{88}==)(?:[^A-Za-z0-9+/=]|$)`),
				tokenType:   "azure-storage-key",
				description: "Azure Storage Account Key",
			},

			// AWS Credentials
			{
				// Matches AWS Access Key ID: starts with AKIA, ASIA, ABIA, ACCA, or A3T[A-Z0-9]
				// followed by 16 base32 characters
				regex:       regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`),
				tokenType:   "aws-access-key-id",
				description: "AWS Access Key ID",
			},

			// Google Cloud Credentials
			{
				// Matches GCP API Key: AIza followed by 35 characters
				regex:       regexp.MustCompile(`\b(AIza[A-Za-z0-9_-]{35})\b`),
				tokenType:   "gcp-api-key",
				description: "Google Cloud API Key",
			},

			// AWS Session Token (labeled)
			{
				regex:       regexp.MustCompile(`(?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)["\s:=]+([A-Za-z0-9+/=]{100,})`),
				tokenType:   "aws-session-token",
				description: "AWS Session Token",
			},

			// AWS STS Session Token (label-free, base64 prefix)
			{
				regex:       regexp.MustCompile(`\b(IQoJb3JpZ2lu[A-Za-z0-9+/=]{100,})\b`),
				tokenType:   "aws-sts-session-token",
				description: "AWS STS Session Token",
			},

			// AWS Secret Access Key (labeled)
			{
				regex:       regexp.MustCompile(`(?:aws_secret_access_key|secret_access_key|SecretAccessKey)["\s:=]+([A-Za-z0-9+/]{40})`),
				tokenType:   "aws-secret-access-key",
				description: "AWS Secret Access Key",
			},
		},
	}
}

// Name returns the detector name
func (d *CloudCredentialsDetector) Name() string {
	return "cloud-credentials"
}

// Detect scans content for cloud provider credentials and returns findings
func (d *CloudCredentialsDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding
	seenCredentials := make(map[string]bool)

	// Check for all credential patterns in order
	for _, pattern := range d.credentialPatterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				// Extract the credential from the capture group
				credential := match[1]

				// Skip if we've already detected this credential
				// This prevents duplicate findings when patterns overlap
				if seenCredentials[credential] {
					continue
				}
				seenCredentials[credential] = true

				findings = append(findings, d.createFinding(credential, pattern, ctx))
			}
		}
	}

	return findings
}

// Redact replaces cloud credentials in content with redaction markers.
func (d *CloudCredentialsDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for detected cloud credentials
func (d *CloudCredentialsDetector) createFinding(credential string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	// All cloud credentials are critical severity (we're only detecting actual secrets now)
	severity := "critical"
	message := fmt.Sprintf(
		"A %s was detected in %s. ",
		pattern.description,
		ctx.FormatSource(),
	)

	return models.Finding{
		ID:          "cloud-credential-" + pattern.tokenType,
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(credential, ctx.FingerprintSalt),
		Severity:    severity,
		Title:       fmt.Sprintf("Cloud Credential Detected (%s)", pattern.description),
		Message:     message,
		Path:        ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
		},
	}
}
