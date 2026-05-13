// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwilioKeyDetector_Detect(t *testing.T) {
	det := NewTwilioKeyDetector()

	tests := []struct {
		name      string
		content   string
		wantCount int
	}{
		{
			name:      "API key SID (lowercase hex)",
			content:   "TWILIO_API_KEY=SK0123456789abcdef0123456789abcdef",
			wantCount: 1,
		},
		{
			name:      "API key SID (uppercase hex)",
			content:   "SK0123456789ABCDEF0123456789ABCDEF",
			wantCount: 1,
		},
		{
			name:      "Account SID is intentionally NOT matched",
			content:   "TWILIO_ACCOUNT_SID=AC0123456789abcdef0123456789abcdef",
			wantCount: 0,
		},
		{
			name:      "SK with too few hex chars",
			content:   "SK0123",
			wantCount: 0,
		},
		{
			name:      "SK with non-hex body",
			content:   "SKzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantCount: 0,
		},
		{
			name: "duplicate SID collapses",
			content: `SK0123456789abcdef0123456789abcdef
again SK0123456789abcdef0123456789abcdef`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := det.Detect(tt.content, testCtx("env:TWILIO_API_KEY"))
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount > 0 {
				f := findings[0]
				assert.Equal(t, "twilio-api-key-sid", f.ID)
				assert.Equal(t, "medium", f.Severity)
				assert.Equal(t, "twilio-api-key-sid", f.Metadata["token_type"])
			}
		})
	}
}

func TestTwilioKeyDetector_Redact(t *testing.T) {
	det := NewTwilioKeyDetector()

	out, counts := det.Redact("SID=SK0123456789abcdef0123456789abcdef")
	assert.Equal(t, "SID=[REDACTED-twilio-api-key-sid]", out)
	assert.Equal(t, 1, counts["REDACTED-twilio-api-key-sid"])
}

func TestTwilioKeyDetector_Name(t *testing.T) {
	assert.Equal(t, "twilio-key", NewTwilioKeyDetector().Name())
}
