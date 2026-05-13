// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// SlackTokenDetector detects Slack workspace and app-level tokens.
//
// Slack tokens come in two prefix families:
//
//   - xox[abprs]- — bot (b), legacy app (a), user (p), refresh (r),
//     session/workspace (s). Body is base32-ish with dashes.
//   - xapp-      — app-level tokens used by Socket Mode connections.
//
// All variants grant API access to a Slack workspace; treat them all
// as critical.
type SlackTokenDetector struct {
	workspacePattern *regexp.Regexp
	appPattern       *regexp.Regexp
	redactPatterns   []RedactPattern
}

// NewSlackTokenDetector creates a new Slack token detector.
func NewSlackTokenDetector() *SlackTokenDetector {
	// 10+ body chars is a deliberate floor — short prefixes alone
	// produce too many false positives in code that mentions Slack
	// without containing real tokens.
	workspace := regexp.MustCompile(`\b(xox[abprs]-[A-Za-z0-9-]{10,})\b`)
	app := regexp.MustCompile(`\b(xapp-[A-Za-z0-9-]{10,})\b`)
	return &SlackTokenDetector{
		workspacePattern: workspace,
		appPattern:       app,
		redactPatterns: []RedactPattern{
			{
				Regex:       workspace,
				Replacement: `[REDACTED-slack-token]`,
				Label:       "REDACTED-slack-token",
				Prefixes:    []string{"xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"},
			},
			{
				Regex:       app,
				Replacement: `[REDACTED-slack-token]`,
				Label:       "REDACTED-slack-token",
				Prefixes:    []string{"xapp-"},
			},
		},
	}
}

// Name returns the detector name.
func (d *SlackTokenDetector) Name() string {
	return "slack-token"
}

// Detect scans content for Slack tokens and returns findings.
func (d *SlackTokenDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	wsMatches := d.workspacePattern.FindAllStringSubmatch(content, -1)
	appMatches := d.appPattern.FindAllStringSubmatch(content, -1)
	findings := make([]models.Finding, 0, len(wsMatches)+len(appMatches))
	seen := make(map[string]bool)

	for _, m := range wsMatches {
		token := m[1]
		if seen[token] {
			continue
		}
		seen[token] = true
		findings = append(findings, d.makeFinding(token, slackPrefixClass(token), ctx))
	}
	for _, m := range appMatches {
		token := m[1]
		if seen[token] {
			continue
		}
		seen[token] = true
		findings = append(findings, d.makeFinding(token, "app", ctx))
	}
	return findings
}

// Redact replaces Slack tokens in content with redaction markers.
func (d *SlackTokenDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// slackPrefixClass maps a token's prefix to its Slack-documented class
// (bot/user/app/refresh/session). The 4th byte of an `xox*-` token is
// the class character; callers must only pass tokens that matched
// workspacePattern.
func slackPrefixClass(token string) string {
	switch token[3] {
	case 'a':
		return "legacy-app"
	case 'b':
		return "bot"
	case 'p':
		return "user"
	case 'r':
		return "refresh"
	case 's':
		return "session"
	default:
		return "workspace"
	}
}

func (d *SlackTokenDetector) makeFinding(
	token string,
	class string,
	ctx *models.DetectionContext,
) models.Finding {
	return models.Finding{
		ID:          "slack-token",
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(token, ctx.FingerprintSalt),
		Severity:    "critical",
		Title:       "Slack Token Detected",
		Description: "A Slack token grants API access to a Slack workspace " +
			"(read messages, post as the token's identity, manage the workspace " +
			"depending on scope). Revoke it from the Slack admin console.",
		Message: fmt.Sprintf("A Slack %s token was detected in %s.", class, ctx.FormatSource()),
		Path:    ctx.Source,
		Metadata: map[string]interface{}{
			"detector_name": d.Name(),
			"token_class":   class,
		},
	}
}
