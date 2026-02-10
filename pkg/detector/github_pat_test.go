// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubTokenDetector_Detect(t *testing.T) {
	detector := NewGitHubPATDetector()

	tests := []struct {
		name          string
		content       string
		source        string
		wantCount     int
		wantTokenType string
	}{
		{
			name:          "detect classic PAT",
			content:       "GITHUB_TOKEN=ghp_1234567890123456789012345678901234AB",
			source:        "env:GITHUB_TOKEN",
			wantCount:     1,
			wantTokenType: "classic-pat",
		},
		{
			name:          "detect fine-grained PAT",
			content:       "token: github_pat_1234567890123456789012_123456789012345678901234567890123456789012345678901234567AB",
			source:        "file:.gitconfig",
			wantCount:     1,
			wantTokenType: "fine-grained-pat",
		},
		{
			name:          "detect OAuth token",
			content:       "OAUTH_TOKEN=gho_1234567890123456789012345678901234AB",
			source:        "env:OAUTH_TOKEN",
			wantCount:     1,
			wantTokenType: "oauth-token",
		},
		{
			name:          "detect GitHub App user-to-server token",
			content:       "APP_TOKEN=ghu_1234567890123456789012345678901234AB",
			source:        "env:APP_TOKEN",
			wantCount:     1,
			wantTokenType: "app-user-token",
		},
		{
			name:          "detect GitHub App server-to-server token",
			content:       "APP_SERVER_TOKEN=ghs_1234567890123456789012345678901234AB",
			source:        "env:APP_SERVER_TOKEN",
			wantCount:     1,
			wantTokenType: "app-server-token",
		},
		{
			name:          "detect GitHub refresh token",
			content:       "REFRESH_TOKEN=ghr_1234567890123456789012345678901234AB",
			source:        "env:REFRESH_TOKEN",
			wantCount:     1,
			wantTokenType: "refresh-token",
		},
		{
			name:      "no token present",
			content:   "SOME_VAR=some_value",
			source:    "env:SOME_VAR",
			wantCount: 0,
		},
		{
			name:      "detect multiple types",
			content:   "ghp_1234567890123456789012345678901234AB and gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
			source:    "file:config.txt",
			wantCount: 2,
		},
		{
			name: "detect all token types",
			content: `
				ghp_1234567890123456789012345678901234AB
				gho_1234567890123456789012345678901234AB
				ghu_1234567890123456789012345678901234AB
				ghs_1234567890123456789012345678901234AB
				ghr_1234567890123456789012345678901234AB
				github_pat_1234567890123456789012_123456789012345678901234567890123456789012345678901234567AB
			`,
			source:    "file:all_tokens.txt",
			wantCount: 6,
		},
		{
			name:      "invalid prefix - too short",
			content:   "ghp_123",
			source:    "test",
			wantCount: 0,
		},
		{
			name:      "multiple tokens of same type",
			content:   "ghp_1234567890123456789012345678901234AB\nghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
			source:    "file:secrets.txt",
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx(tt.source))

			assert.Len(t, findings, tt.wantCount, "Expected %d findings", tt.wantCount)

			if tt.wantCount > 0 && tt.wantTokenType != "" {
				// Check that at least one finding has the expected token type
				found := false
				for _, f := range findings {
					if tokenType, ok := f.Metadata["token_type"].(string); ok && tokenType == tt.wantTokenType {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected to find token_type=%s in findings metadata", tt.wantTokenType)
			}

			// Verify all findings have required fields
			for i, f := range findings {
				assert.NotEmpty(t, f.ID, "Finding %d missing ID", i)
				assert.NotEmpty(t, f.Severity, "Finding %d missing Severity", i)
				assert.NotEmpty(t, f.Title, "Finding %d missing Title", i)
				assert.NotEmpty(t, f.Message, "Finding %d missing Message", i)
				assert.NotNil(t, f.Metadata, "Finding %d missing Metadata", i)
			}
		})
	}
}

func TestGitHubTokenDetector_Name(t *testing.T) {
	detector := NewGitHubPATDetector()
	assert.Equal(t, "github-token", detector.Name())
}

func TestGitHubTokenDetector_RedactedToken(t *testing.T) {
	detector := NewGitHubPATDetector()
	content := "GITHUB_TOKEN=ghp_1234567890123456789012345678901234AB"
	findings := detector.Detect(content, testCtx("test"))

	require.Len(t, findings, 1, "Expected exactly 1 finding")

	// Verify the token type is present
	tokenType, ok := findings[0].Metadata["token_type"].(string)
	require.True(t, ok, "token_type not found in metadata")
	assert.Equal(t, "classic-pat", tokenType)

	// Verify the full token is not in the message
	fullToken := "ghp_1234567890123456789012345678901234AB"
	assert.NotContains(t, findings[0].Message, fullToken, "Full token should not appear in the message")
}

func TestGitHubTokenDetector_AllTokenTypes(t *testing.T) {
	detector := NewGitHubPATDetector()

	tokenTests := []struct {
		prefix      string
		tokenType   string
		description string
	}{
		{"ghp", "classic-pat", "Classic Personal Access Token"},
		{"gho", "oauth-token", "OAuth Access Token"},
		{"ghu", "app-user-token", "GitHub App User-to-Server Token"},
		{"ghs", "app-server-token", "GitHub App Server-to-Server Token"},
		{"ghr", "refresh-token", "GitHub Refresh Token"},
	}

	for _, tt := range tokenTests {
		t.Run(tt.prefix, func(t *testing.T) {
			// Generate a valid token for this prefix
			token := tt.prefix + "_1234567890123456789012345678901234AB"
			findings := detector.Detect(token, testCtx("test"))

			require.Len(t, findings, 1, "Expected exactly 1 finding")

			// Verify token type
			tokenType, ok := findings[0].Metadata["token_type"].(string)
			require.True(t, ok, "token_type not found in metadata")
			assert.Equal(t, tt.tokenType, tokenType)

			// Verify description
			description, ok := findings[0].Metadata["description"].(string)
			require.True(t, ok, "description not found in metadata")
			assert.Equal(t, tt.description, description)
		})
	}
}
