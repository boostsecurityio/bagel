// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// DatabaseConnectionDetector detects database connection URLs that embed
// credentials in the userinfo segment (e.g. postgres://user:pw@host/db).
// URLs without an embedded password (postgres://host/db,
// postgres://user@host/db) are not credentials and not reported.
type DatabaseConnectionDetector struct {
	pattern        *regexp.Regexp
	redactPatterns []RedactPattern
}

// dbConnectionRegex matches <scheme>://[user]:password@host[:port][/path]
// for the database/queue schemes most commonly seen in dev configs.
// The userinfo half allows an empty username (e.g. redis://:pw@host) but
// requires a non-empty password — that's the bit that makes it a credential.
var dbConnectionRegex = regexp.MustCompile(
	`\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|clickhouse|mssql)://` +
		`([^:@/\s"'<>]*):([^@/\s"'<>]+)@` +
		`([^/\s"'<>?#]+)`,
)

// NewDatabaseConnectionDetector creates a new database connection URL detector.
func NewDatabaseConnectionDetector() *DatabaseConnectionDetector {
	return &DatabaseConnectionDetector{
		pattern: dbConnectionRegex,
		redactPatterns: []RedactPattern{
			{
				// Preserve scheme://user@host so the redacted file is
				// still readable; only the password vanishes.
				Regex:       dbConnectionRegex,
				Replacement: `${1}://${2}:[REDACTED-db-credential]@${4}`,
				Label:       "REDACTED-db-credential",
				Prefixes: []string{
					"postgres://", "postgresql://", "mysql://", "mariadb://",
					"mongodb://", "mongodb+srv://", "redis://", "rediss://",
					"amqp://", "amqps://", "clickhouse://", "mssql://",
				},
			},
		},
	}
}

// Name returns the detector name.
func (d *DatabaseConnectionDetector) Name() string {
	return "database-connection-string"
}

// Detect scans content for database connection URLs with embedded
// passwords and returns findings.
func (d *DatabaseConnectionDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	matches := d.pattern.FindAllStringSubmatch(content, -1)
	findings := make([]models.Finding, 0, len(matches))
	seen := make(map[string]bool, len(matches))

	for _, m := range matches {
		full := m[0]
		if seen[full] {
			continue
		}
		seen[full] = true

		scheme := strings.ToLower(m[1])
		username := m[2]
		host := m[4]

		findings = append(findings, models.Finding{
			ID:          "database-connection-string",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.SaltedFingerprint(full, ctx.FingerprintSalt),
			Severity:    "critical",
			Title:       "Database Connection String With Embedded Credential Detected",
			Description: "A database/queue connection URL embeds a password in the userinfo segment. " +
				"Move the credential to a secret manager or env variable referenced by the URL " +
				"(some clients support ${ENV} expansion).",
			Message: fmt.Sprintf("A %s connection string with embedded credentials was detected in %s.",
				scheme, ctx.FormatSource()),
			Path: ctx.Source,
			Metadata: map[string]interface{}{
				"detector_name":    d.Name(),
				"scheme":           scheme,
				"host":             host,
				"username_present": username != "",
			},
		})
	}
	return findings
}

// Redact replaces password components in detected URLs with a redaction
// marker, leaving scheme/user/host intact.
func (d *DatabaseConnectionDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
