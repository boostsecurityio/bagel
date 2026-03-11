// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// SSHPrivateKeyDetector detects SSH private keys in content
type SSHPrivateKeyDetector struct {
	keyPattern     *regexp.Regexp
	redactPatterns []RedactPattern
}

// NewSSHPrivateKeyDetector creates a new SSH private key detector
func NewSSHPrivateKeyDetector() *SSHPrivateKeyDetector {
	// Regex pattern to detect various SSH private key formats
	// Matches: RSA, DSA, EC, OPENSSH, ENCRYPTED, etc.
	pattern := regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)

	return &SSHPrivateKeyDetector{
		keyPattern: pattern,
		redactPatterns: []RedactPattern{
			{
				Regex: regexp.MustCompile(
					`-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----` +
						`[A-Za-z0-9+/=\s\\n]{20,}` +
						`-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----`),
				Replacement: `[REDACTED-ssh-private-key]`,
				Label:       "REDACTED-ssh-private-key",
				Prefixes:    []string{"-----BEGIN"},
			},
		},
	}
}

// Name returns the detector name
func (d *SSHPrivateKeyDetector) Name() string {
	return "ssh-private-key"
}

// Detect scans content for SSH private keys and returns findings
func (d *SSHPrivateKeyDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	matches := d.keyPattern.FindAllString(content, -1)
	findings := make([]models.Finding, 0, len(matches))

	for _, match := range matches {
		keyType := d.determineKeyType(match)
		isEncrypted := d.isEncrypted(match)

		findings = append(findings, d.createFinding(match, keyType, isEncrypted, ctx))
	}

	return findings
}

// determineKeyType extracts the key type from the BEGIN marker
func (d *SSHPrivateKeyDetector) determineKeyType(keyContent string) string {
	// Extract text between "BEGIN" and "PRIVATE KEY"
	beginPattern := regexp.MustCompile(`(?i)-----BEGIN\s+([A-Z0-9_-]+)\s+PRIVATE KEY`)
	matches := beginPattern.FindStringSubmatch(keyContent)

	if len(matches) >= 2 {
		return strings.ToUpper(matches[1])
	}

	// Check for PKCS#8 format (-----BEGIN PRIVATE KEY----- without a type prefix)
	// This is different from OPENSSH format (-----BEGIN OPENSSH PRIVATE KEY-----)
	if strings.Contains(strings.ToUpper(keyContent), "BEGIN PRIVATE KEY") {
		return "PKCS8"
	}

	return "UNKNOWN"
}

// isEncrypted checks if the private key is encrypted (password-protected)
func (d *SSHPrivateKeyDetector) isEncrypted(keyContent string) bool {
	upperContent := strings.ToUpper(keyContent)

	// Check for traditional PEM format encryption indicators
	// These are typically in headers before the base64 block
	if strings.Contains(upperContent, "ENCRYPTED") {
		return true
	}

	// Specific PEM encryption headers
	if strings.Contains(keyContent, "Proc-Type: 4,ENCRYPTED") {
		return true
	}

	if strings.Contains(keyContent, "DEK-Info:") {
		return true
	}

	// For OPENSSH format keys, the cipher and KDF names are stored as length-prefixed
	// strings in the binary format (4-byte big-endian length followed by the string).
	// When the binary data is base64-encoded, the cipher names appear as base64 substrings.
	//
	// We search for base64-encoded cipher names. These patterns are specific enough to
	// avoid false positives (unlike searching for plaintext "AES" or "BCRYPT").
	//
	// Common AES ciphers (base64 encodings):
	opensshCipherPatterns := []string{
		"YWVzMTI4LWN0cg", // "aes128-ctr"
		"YWVzMTkyLWN0cg", // "aes192-ctr"
		"YWVzMjU2LWN0cg", // "aes256-ctr"
		"YWVzMTI4LWNiYw", // "aes128-cbc"
		"YWVzMTkyLWNiYw", // "aes192-cbc"
		"YWVzMjU2LWNiYw", // "aes256-cbc"
	}

	for _, pattern := range opensshCipherPatterns {
		if strings.Contains(keyContent, pattern) {
			return true
		}
	}

	// Check for bcrypt KDF in OPENSSH format
	// "YmNyeXB0" is the base64 encoding of "bcrypt"
	// This is specific enough to not cause false positives
	if strings.Contains(keyContent, "YmNyeXB0") {
		return true
	}

	// For OPENSSH keys, check if the cipher is "none"
	// "bm9uZQ" is the base64 encoding of "none" (without padding)
	if strings.Contains(upperContent, "OPENSSH") && strings.Contains(keyContent, "bm9uZQ") {
		return false
	}

	return false
}

// Redact replaces SSH private keys in content with redaction markers.
func (d *SSHPrivateKeyDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for a detected SSH private key
func (d *SSHPrivateKeyDetector) createFinding(keyContent, keyType string, isEncrypted bool, ctx *models.DetectionContext) models.Finding {
	var severity string
	var title string
	var message string

	if isEncrypted {
		severity = "low"
		title = fmt.Sprintf("Encrypted SSH Private Key Detected (%s)", keyType)
		message = fmt.Sprintf(
			"An encrypted %s SSH private key was detected in %s. "+
				"The key is password-protected, which is a good security practice. "+
				"Ensure the key file has appropriate permissions (0600) and the password is strong.",
			keyType,
			ctx.FormatSource(),
		)
	} else {
		severity = "critical"
		title = fmt.Sprintf("Unencrypted SSH Private Key Detected (%s)", keyType)
		message = fmt.Sprintf(
			"An unencrypted %s SSH private key was detected in %s. "+
				"This key is NOT password-protected, which poses a significant security risk. "+
				"Anyone with access to this file can use it to authenticate. "+
				"Recommendation: Regenerate this key with a strong passphrase using 'ssh-keygen -p -f <keyfile>'.",
			keyType,
			ctx.FormatSource(),
		)
	}

	return models.Finding{
		ID:          "ssh-private-key-" + strings.ToLower(keyType),
		Fingerprint: models.Fingerprint(keyContent),
		Severity:    severity,
		Title:       title,
		Message:     message,
		Path:        ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"key_type":      keyType,
			"is_encrypted":  isEncrypted,
		},
	}
}
