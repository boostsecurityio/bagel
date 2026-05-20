// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlackTokenDetector_Detect(t *testing.T) {
	det := NewSlackTokenDetector()

	tests := []struct {
		name      string
		content   string
		wantCount int
		wantClass string
	}{
		{
			name:      "bot token",
			content:   `SLACK_BOT_TOKEN=xoxb-123456789012-345678901234-abcdef0123456789ABCDEFGH`,
			wantCount: 1,
			wantClass: "bot",
		},
		{
			name:      "user token",
			content:   `xoxp-1234567890-987654321-abcdefghijklmnop`,
			wantCount: 1,
			wantClass: "user",
		},
		{
			name:      "legacy app token",
			content:   `legacy=xoxa-1234567890abcdef`,
			wantCount: 1,
			wantClass: "legacy-app",
		},
		{
			name:      "refresh token",
			content:   `xoxr-1234567890abcdef-extra`,
			wantCount: 1,
			wantClass: "refresh",
		},
		{
			name:      "app-level token (Socket Mode)",
			content:   `xapp-1-A0123456789-1234567890123-abcdef0123456789`,
			wantCount: 1,
			wantClass: "app",
		},
		{
			name:      "short prefix without enough body — ignored",
			content:   `xoxb-short`,
			wantCount: 0,
		},
		{
			name:      "non-token text mentioning Slack",
			content:   `slack token rotation procedure`,
			wantCount: 0,
		},
		{
			name: "duplicate token collapses to one finding",
			content: `first xoxb-1111111111-2222222222-aaaaaaaaaaaaaaaaaaaaaaaa
second xoxb-1111111111-2222222222-aaaaaaaaaaaaaaaaaaaaaaaa`,
			wantCount: 1,
			wantClass: "bot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := det.Detect(tt.content, testCtx("env:SLACK_BOT_TOKEN"))
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount > 0 {
				f := findings[0]
				assert.Equal(t, "slack-token", f.ID)
				assert.Equal(t, "critical", f.Severity)
				assert.Equal(t, tt.wantClass, f.Metadata["token_class"])
			}
		})
	}
}

func TestSlackTokenDetector_Redact(t *testing.T) {
	det := NewSlackTokenDetector()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "redact xoxb",
			input: "TOKEN=xoxb-1-2-aaaaaaaaaaaaaaaaaaaaaaaaa",
			want:  "TOKEN=[REDACTED-slack-token]",
		},
		{
			name:  "redact xapp",
			input: "APP=xapp-1-A0-1234567890-aaaaaaaaaaaaaaaaaaaaaaaa",
			want:  "APP=[REDACTED-slack-token]",
		},
		{
			name:  "no token — untouched",
			input: "regular text",
			want:  "regular text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := det.Redact(tt.input)
			assert.Equal(t, tt.want, out)
		})
	}
}

func TestSlackTokenDetector_Name(t *testing.T) {
	assert.Equal(t, "slack-token", NewSlackTokenDetector().Name())
}
