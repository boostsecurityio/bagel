// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStripeKeyDetector_Detect(t *testing.T) {
	det := NewStripeKeyDetector()

	tests := []struct {
		name      string
		content   string
		wantID    string
		wantKind  string
		wantEnv   string
		wantSev   string
		wantCount int
	}{
		{
			name:      "live secret key",
			content:   "STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuvwx",
			wantID:    "stripe-secret-key",
			wantKind:  "secret",
			wantEnv:   "live",
			wantSev:   "critical",
			wantCount: 1,
		},
		{
			name:      "test secret key",
			content:   "STRIPE_SECRET_KEY=sk_test_abcdefghijklmnopqrstuvwx",
			wantID:    "stripe-secret-key",
			wantKind:  "secret",
			wantEnv:   "test",
			wantSev:   "high",
			wantCount: 1,
		},
		{
			name:      "live restricted key",
			content:   "key=rk_live_abcdefghijklmnopqrstuvwx",
			wantID:    "stripe-secret-key",
			wantKind:  "secret",
			wantEnv:   "live",
			wantSev:   "critical",
			wantCount: 1,
		},
		{
			name:      "live publishable key — informational",
			content:   "STRIPE_PUB=pk_live_abcdefghijklmnopqrstuvwx",
			wantID:    "stripe-publishable-key",
			wantKind:  "publishable",
			wantEnv:   "live",
			wantSev:   "low",
			wantCount: 1,
		},
		{
			name:      "no Stripe key — sk_other_ prefix is not a stripe key",
			content:   "sk_other_abcdefghijklmnopqrstuvwx",
			wantCount: 0,
		},
		{
			name:      "too short body — not a Stripe key",
			content:   "sk_live_short",
			wantCount: 0,
		},
		{
			name: "secret + publishable in same file produces two findings",
			content: `STRIPE_SECRET_KEY=sk_live_aaaaaaaaaaaaaaaaaaaaaaaa
STRIPE_PUB_KEY=pk_live_bbbbbbbbbbbbbbbbbbbbbbbb`,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := det.Detect(tt.content, testCtx("env:STRIPE"))
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount == 1 {
				f := findings[0]
				assert.Equal(t, tt.wantID, f.ID)
				assert.Equal(t, tt.wantSev, f.Severity)
				assert.Equal(t, tt.wantKind, f.Metadata["key_kind"])
				assert.Equal(t, tt.wantEnv, f.Metadata["environment"])
			}
		})
	}
}

func TestStripeKeyDetector_Redact(t *testing.T) {
	det := NewStripeKeyDetector()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "secret key redacted",
			input: "k=sk_live_abcdefghijklmnopqrstuvwx",
			want:  "k=[REDACTED-stripe-secret-key]",
		},
		{
			name:  "restricted key redacted",
			input: "k=rk_test_abcdefghijklmnopqrstuvwx",
			want:  "k=[REDACTED-stripe-secret-key]",
		},
		{
			name:  "publishable key NOT redacted (meant to be public)",
			input: "k=pk_live_abcdefghijklmnopqrstuvwx",
			want:  "k=pk_live_abcdefghijklmnopqrstuvwx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := det.Redact(tt.input)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestStripeKeyDetector_Name(t *testing.T) {
	assert.Equal(t, "stripe-key", NewStripeKeyDetector().Name())
}
