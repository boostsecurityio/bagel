// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMTokenDetector_Detect(t *testing.T) {
	detector := NewNPMTokenDetector()

	tests := []struct {
		name          string
		content       string
		source        string
		wantCount     int
		wantTokenType string
	}{
		{
			name:          "detect npm_ token in authToken field",
			content:       "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890",
			source:        "file:.npmrc",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with spaces",
			content:       ":_authToken = npm_abcdefghijklmnopqrstuvwxyz1234567890",
			source:        "file:.npmrc",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with quotes",
			content:       "npmAuthToken: \"npm_abcdefghijklmnopqrstuvwxyz1234567890\"",
			source:        "file:.yarnrc.yml",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with single quotes",
			content:       "npmAuthToken='npm_abcdefghijklmnopqrstuvwxyz1234567890'",
			source:        "file:.yarnrc",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with backticks",
			content:       "const token = `npm_abcdefghijklmnopqrstuvwxyz1234567890`;",
			source:        "file:script.js",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token at end of line",
			content:       "NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890",
			source:        "file:.env",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with newline after",
			content:       "token=npm_abcdefghijklmnopqrstuvwxyz1234567890\nother=value",
			source:        "file:.env",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:          "detect npm_ token with semicolon after",
			content:       "const token = npm_abcdefghijklmnopqrstuvwxyz1234567890; console.log(token);",
			source:        "file:script.js",
			wantCount:     1,
			wantTokenType: "npm-auth-token",
		},
		{
			name:      "no token present",
			content:   "registry=https://registry.npmjs.org/",
			source:    "file:.npmrc",
			wantCount: 0,
		},
		{
			name:      "token too short - npm_abc",
			content:   ":_authToken=npm_abc",
			source:    "file:.npmrc",
			wantCount: 0,
		},
		{
			name:      "npm prefix but not npm_ format",
			content:   "//registry.npmjs.org/:_authToken=npmabc123456789012345678901234567890",
			source:    "file:.npmrc",
			wantCount: 0,
		},
		{
			name: "detect multiple npm_ tokens",
			content: `//registry.npmjs.org/:_authToken=npm_token1234567890123456789012345678901
//npm.pkg.github.com/:_authToken=npm_token2234567890123456789012345678901`,
			source:    "file:.npmrc",
			wantCount: 2,
		},
		{
			name: "real-world npmrc example",
			content: `//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890
registry=https://registry.npmjs.org/
always-auth=true`,
			source:    "file:.npmrc",
			wantCount: 1,
		},
		{
			name: "real-world yarnrc.yml example",
			content: `npmRegistries:
  "https://registry.yarnpkg.com":
    npmAuthToken: "npm_abcdefghijklmnopqrstuvwxyz1234567890"`,
			source:    "file:.yarnrc.yml",
			wantCount: 1,
		},
		{
			name:      "token in middle of line with surrounding text",
			content:   "some text npm_abcdefghijklmnopqrstuvwxyz1234567890 more text",
			source:    "file:config.txt",
			wantCount: 1,
		},
		{
			name:      "commented out token - still detected",
			content:   "# :_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890",
			source:    "file:.npmrc",
			wantCount: 1,
		},
		{
			name:      "case insensitive - NPM_ uppercase",
			content:   ":_authToken=NPM_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
			source:    "file:.npmrc",
			wantCount: 1,
		},
		{
			name:      "case insensitive - NpM_ mixed case",
			content:   ":_authToken=NpM_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
			source:    "file:.npmrc",
			wantCount: 1,
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
				assert.Equal(t, "npm-token-npm-auth-token", f.ID, "Finding %d has wrong ID", i)
				assert.NotEmpty(t, f.Severity, "Finding %d missing Severity", i)
				assert.NotEmpty(t, f.Title, "Finding %d missing Title", i)
				assert.NotEmpty(t, f.Message, "Finding %d missing Message", i)
				assert.NotNil(t, f.Metadata, "Finding %d missing Metadata", i)
				assert.Equal(t, "critical", f.Severity, "NPM tokens should be critical severity")
			}
		})
	}
}

func TestNPMTokenDetector_Metadata(t *testing.T) {
	detector := NewNPMTokenDetector()
	content := ":_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890"
	findings := detector.Detect(content, testCtx("test"))

	require.Len(t, findings, 1, "Expected exactly 1 finding")

	// Verify token type
	tokenType, ok := findings[0].Metadata["token_type"].(string)
	require.True(t, ok, "token_type not found in metadata")
	assert.Equal(t, "npm-auth-token", tokenType)

	// Verify description
	description, ok := findings[0].Metadata["description"].(string)
	require.True(t, ok, "description not found in metadata")
	assert.Equal(t, "NPM Authentication Token", description)

	// Verify detector name
	detectorName, ok := findings[0].Metadata["detector_name"].(string)
	require.True(t, ok, "detector_name not found in metadata")
	assert.Equal(t, "npm-token", detectorName)
}

func TestNPMTokenDetector_EdgeCases(t *testing.T) {
	detector := NewNPMTokenDetector()

	tests := []struct {
		name      string
		content   string
		wantCount int
	}{
		{
			name:      "empty string",
			content:   "",
			wantCount: 0,
		},
		{
			name:      "only whitespace",
			content:   "   \n\t  ",
			wantCount: 0,
		},
		{
			name:      "npm_ without enough characters",
			content:   "npm_short",
			wantCount: 0,
		},
		{
			name:      "npm without underscore",
			content:   "npmabc1234567890123456789012345678901234",
			wantCount: 0,
		},
		{
			name:      "token at start of string",
			content:   "npm_abcdefghijklmnopqrstuvwxyz1234567890 is the token",
			wantCount: 1,
		},
		{
			name:      "token at end of string",
			content:   "the token is npm_abcdefghijklmnopqrstuvwxyz1234567890",
			wantCount: 1,
		},
		{
			name:      "multiple tokens same value",
			content:   "npm_abcdefghijklmnopqrstuvwxyz1234567890 and npm_abcdefghijklmnopqrstuvwxyz1234567890",
			wantCount: 1, // Deduplication should prevent duplicates
		},
		{
			name:      "token with escaped characters before",
			content:   "token\\n npm_abcdefghijklmnopqrstuvwxyz1234567890",
			wantCount: 1,
		},
		{
			name:      "token with escaped characters after",
			content:   "npm_abcdefghijklmnopqrstuvwxyz1234567890\\r\\nmore",
			wantCount: 1,
		},
		{
			name:      "token in JSON",
			content:   `{"token": "npm_abcdefghijklmnopqrstuvwxyz1234567890"}`,
			wantCount: 1,
		},
		{
			name:      "token in YAML",
			content:   "token: npm_abcdefghijklmnopqrstuvwxyz1234567890",
			wantCount: 1,
		},
		{
			name:      "token in shell script",
			content:   "export NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz1234567890",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test"))
			assert.Len(t, findings, tt.wantCount)
		})
	}
}

func TestNPMTokenDetector_Deduplication(t *testing.T) {
	detector := NewNPMTokenDetector()

	// Same token appearing multiple times should only be reported once
	content := `
	npm_abcdefghijklmnopqrstuvwxyz1234567890
	npm_abcdefghijklmnopqrstuvwxyz1234567890
	npm_abcdefghijklmnopqrstuvwxyz1234567890
	`
	findings := detector.Detect(content, testCtx("test"))

	assert.Len(t, findings, 1, "Duplicate tokens should be deduplicated")
}

func TestNPMTokenDetector_MultipleUniqueTokens(t *testing.T) {
	detector := NewNPMTokenDetector()

	// Different tokens should all be detected
	content := `
	npm_token1234567890123456789012345678901
	npm_token2234567890123456789012345678901
	npm_token3234567890123456789012345678901
	`
	findings := detector.Detect(content, testCtx("test"))

	assert.Len(t, findings, 3, "Each unique token should be detected")
}
