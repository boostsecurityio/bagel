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
}

// NewCloudCredentialsDetector creates a new cloud credentials detector
func NewCloudCredentialsDetector() *CloudCredentialsDetector {
	return &CloudCredentialsDetector{
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
		ID:       "cloud-credential-" + pattern.tokenType,
		Severity: severity,
		Title:    fmt.Sprintf("Cloud Credential Detected (%s)", pattern.description),
		Message:  message,
		Path:     ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_type":    pattern.tokenType,
			"description":   pattern.description,
			"fingerprint":   Fingerprint(credential),
		},
	}
}
