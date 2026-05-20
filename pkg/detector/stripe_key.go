// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"fmt"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// StripeKeyDetector detects Stripe API keys. Stripe uses three prefix
// families:
//
//   - sk_(live|test)_…  — Secret key. Full Stripe API access (live), or
//     test-mode access (test).
//   - rk_(live|test)_…  — Restricted key. Same shape as sk_, scoped by
//     roles configured in the Stripe dashboard.
//   - pk_(live|test)_…  — Publishable key. Not a secret per Stripe
//     (designed to ship in client-side JS), but worth surfacing because
//     leaking it can enable fraudulent Element/Checkout usage and
//     people frequently confuse it with the secret key.
//
// IDs split secret vs publishable so callers can filter; severities
// reflect how much damage a leaked key enables.
type StripeKeyDetector struct {
	secretPattern      *regexp.Regexp
	restrictedPattern  *regexp.Regexp
	publishablePattern *regexp.Regexp
	redactPatterns     []RedactPattern
}

// NewStripeKeyDetector creates a new Stripe API key detector.
func NewStripeKeyDetector() *StripeKeyDetector {
	// Stripe keys are alphanumeric after the prefix. 24 chars is the
	// shortest observed body; live keys are typically 100+, test keys
	// 24+. Loosen to 24 to also catch older keys still in circulation.
	secret := regexp.MustCompile(`\b(sk_(live|test)_[A-Za-z0-9]{24,})\b`)
	restricted := regexp.MustCompile(`\b(rk_(live|test)_[A-Za-z0-9]{24,})\b`)
	publishable := regexp.MustCompile(`\b(pk_(live|test)_[A-Za-z0-9]{24,})\b`)
	return &StripeKeyDetector{
		secretPattern:      secret,
		restrictedPattern:  restricted,
		publishablePattern: publishable,
		// Redact only secret + restricted. Publishable keys are
		// intentionally exposed (web pages, mobile apps); redacting
		// them in shared logs/scrubs would break legitimate uses.
		redactPatterns: []RedactPattern{
			{
				Regex:       secret,
				Replacement: `[REDACTED-stripe-secret-key]`,
				Label:       "REDACTED-stripe-secret-key",
				Prefixes:    []string{"sk_live_", "sk_test_"},
			},
			{
				Regex:       restricted,
				Replacement: `[REDACTED-stripe-secret-key]`,
				Label:       "REDACTED-stripe-secret-key",
				Prefixes:    []string{"rk_live_", "rk_test_"},
			},
		},
	}
}

// Name returns the detector name.
func (d *StripeKeyDetector) Name() string {
	return "stripe-key"
}

// Detect scans content for Stripe API keys and returns findings.
func (d *StripeKeyDetector) Detect(
	content string,
	ctx *models.DetectionContext,
) []models.Finding {
	findings := make([]models.Finding, 0, 4)
	seen := make(map[string]bool)

	// kind is the human-readable variant label ("secret" / "restricted"
	// / "publishable"). It's tracked explicitly so the message/metadata
	// reflect the actual key family — secret and restricted share a
	// finding ID for filter convenience, so we can't derive kind from ID.
	type variant struct {
		pattern    *regexp.Regexp
		id         string
		kind       string
		title      string
		descPrefix string
		liveSev    string
		testSev    string
	}
	variants := []variant{
		{
			pattern:    d.secretPattern,
			id:         "stripe-secret-key",
			kind:       "secret",
			title:      "Stripe Secret Key Detected",
			descPrefix: "Stripe secret key — full API access to the Stripe account.",
			liveSev:    "critical",
			testSev:    "high",
		},
		{
			pattern:    d.restrictedPattern,
			id:         "stripe-secret-key",
			kind:       "restricted",
			title:      "Stripe Restricted Key Detected",
			descPrefix: "Stripe restricted key — scoped API access set in the dashboard.",
			liveSev:    "critical",
			testSev:    "high",
		},
		{
			pattern: d.publishablePattern,
			id:      "stripe-publishable-key",
			kind:    "publishable",
			title:   "Stripe Publishable Key Detected",
			descPrefix: "Stripe publishable key — designed to ship in client-side code, " +
				"so not strictly a secret, but a leak can enable fraudulent Checkout/Element use.",
			liveSev: "low",
			testSev: "low",
		},
	}

	for _, v := range variants {
		for _, m := range v.pattern.FindAllStringSubmatch(content, -1) {
			token := m[1]
			env := m[2] // "live" or "test"
			if seen[token] {
				continue
			}
			seen[token] = true

			severity := v.liveSev
			if env == "test" {
				severity = v.testSev
			}

			findings = append(findings, models.Finding{
				ID:          v.id,
				Type:        models.FindingTypeSecret,
				Fingerprint: models.SaltedFingerprint(token, ctx.FingerprintSalt),
				Severity:    severity,
				Title:       v.title,
				Description: v.descPrefix + " Rotate the key from the Stripe dashboard.",
				Message:     fmt.Sprintf("A Stripe %s key (%s mode) was detected in %s.", v.kind, env, ctx.FormatSource()),
				Path:        ctx.Source,
				Metadata: map[string]interface{}{
					"detector_name": d.Name(),
					"key_kind":      v.kind,
					"environment":   env,
				},
			})
		}
	}
	return findings
}

// Redact replaces Stripe secret/restricted keys with redaction markers.
// Publishable keys are intentionally left alone.
func (d *StripeKeyDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}
