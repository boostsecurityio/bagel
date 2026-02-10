// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPAuthDetector_Name(t *testing.T) {
	detector := NewHTTPAuthDetector()
	assert.Equal(t, "http-authentication", detector.Name())
}

func TestHTTPAuthDetector_DetectBearerToken(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Bearer token in Authorization header",
			content:       `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:          "Bearer token in curl command",
			content:       `curl -H "Authorization: Bearer abc123def456ghi789jkl"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:          "Token format (alternative to Bearer)",
			content:       `Authorization: Token sk_live_abcd1234567890`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:          "Api-Token format",
			content:       `Authorization: Api-Token my_secret_token_123`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:          "Case insensitive bearer",
			content:       `authorization: bearer test_token_value_here`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:          "Token in config file",
			content:       `Authorization: Bearer prod_api_key_xyz789`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-bearer-token",
		},
		{
			name:         "Too short token (less than 16 chars)",
			content:      `Authorization: Bearer short123`,
			shouldDetect: false,
		},
		{
			name:         "No bearer keyword",
			content:      `Authorization: abc123def456`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect bearer token")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "Bearer Token")
				assert.Equal(t, "http-authentication", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestHTTPAuthDetector_DetectBasicAuth(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Basic auth in Authorization header",
			content:       `Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth",
		},
		{
			name:          "Basic auth in curl command",
			content:       `curl -H "Authorization: Basic YWRtaW46c2VjcmV0MTIz"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth",
		},
		{
			name:          "Case insensitive basic",
			content:       `authorization: basic dGVzdDp0ZXN0MTIzNDU2`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth",
		},
		{
			name:          "Basic auth with padding",
			content:       `Authorization: Basic dXNlcjpwYXNzd29yZA==`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth",
		},
		{
			name:         "Too short base64",
			content:      `Authorization: Basic abc123`,
			shouldDetect: false,
		},
		{
			name:         "Invalid base64 characters",
			content:      `Authorization: Basic invalid@#$%chars`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect basic auth")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "Basic Authentication")
				assert.Equal(t, "http-authentication", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestHTTPAuthDetector_DetectAPIKeyHeader(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "X-API-Key header",
			content:       `X-API-Key: sk_live_abcdef123456`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:          "X-Api-Key header (mixed case)",
			content:       `X-Api-Key: my_secret_api_key_value`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:          "API-Key header (no X prefix)",
			content:       `API-Key: prod_key_xyz789abc`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:          "Api-Token header",
			content:       `Api-Token: token_1234567890abcdef`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:          "X-API-Token header",
			content:       `X-API-Token: secret_token_value_here`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:          "In curl command",
			content:       `curl -H "X-API-Key: sk_test_1234567890" https://api.example.com`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-api-key-header",
		},
		{
			name:         "Too short API key",
			content:      `X-API-Key: short`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect API key")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "API Key")
				assert.Equal(t, "http-authentication", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestHTTPAuthDetector_DetectBasicAuthURL(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Basic auth in HTTP URL",
			content:       `http://user:password@example.com/api`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth-url",
		},
		{
			name:          "Basic auth in HTTPS URL",
			content:       `https://admin:secret123@api.example.com`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth-url",
		},
		{
			name:          "Basic auth in git clone command",
			content:       `git clone https://user:pass123@github.com/repo/project.git`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth-url",
		},
		{
			name:          "FTP with credentials",
			content:       `ftp://ftpuser:ftppass@ftp.example.com/path`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth-url",
		},
		{
			name:          "URL with complex password",
			content:       `https://service:P4ssw0rd!@api.internal.com`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "http-auth-basic-auth-url",
		},
		{
			name:         "URL without credentials",
			content:      `https://example.com/api`,
			shouldDetect: false,
		},
		{
			name:         "Too short username",
			content:      `https://ab:password@example.com`,
			shouldDetect: false,
		},
		{
			name:         "Too short password",
			content:      `https://username:pw@example.com`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect URL credentials")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "Basic Authentication in URL")
				assert.Equal(t, "http-authentication", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestHTTPAuthDetector_DetectMultiple(t *testing.T) {
	detector := NewHTTPAuthDetector()

	content := `
# API Configuration
Authorization: Bearer prod_token_abc123xyz789
X-API-Key: sk_live_1234567890abcdef
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
git clone https://user:password@github.com/repo.git
`

	findings := detector.Detect(content, testCtx("config.txt"))

	require.GreaterOrEqual(t, len(findings), 4, "Should detect all authentication types")

	// Check that we found all types
	foundTypes := make(map[string]bool)
	for _, finding := range findings {
		foundTypes[finding.ID] = true
		assert.Equal(t, "critical", finding.Severity)
		assert.Equal(t, "http-authentication", finding.Metadata["detector_name"])
	}

	assert.True(t, foundTypes["http-auth-bearer-token"], "Should detect bearer token")
	assert.True(t, foundTypes["http-auth-api-key-header"], "Should detect API key")
	assert.True(t, foundTypes["http-auth-basic-auth"], "Should detect basic auth header")
	assert.True(t, foundTypes["http-auth-basic-auth-url"], "Should detect URL credentials")
}

func TestHTTPAuthDetector_NoFalsePositives(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Normal text",
			content: `This is just normal text without any credentials`,
		},
		{
			name:    "Authorization mention without credential",
			content: `The Authorization header should contain a valid token`,
		},
		{
			name:    "URL without credentials",
			content: `https://api.example.com/v1/users`,
		},
		{
			name:    "Short values",
			content: `Authorization: Bearer abc`,
		},
		{
			name:    "Code example with placeholder",
			content: `Authorization: Bearer YOUR_TOKEN_HERE`,
		},
		{
			name:    "Environment variable reference",
			content: `Authorization: Bearer $API_TOKEN`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))
			assert.Empty(t, findings, "Should not produce false positives")
		})
	}
}

func TestHTTPAuthDetector_RealWorldExamples(t *testing.T) {
	detector := NewHTTPAuthDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
	}{
		{
			name: "GitHub API call",
			content: `curl -H "Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwxyz" \
  https://api.github.com/user/repos`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "JWT token in request",
			content:       `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Stripe API key",
			content:       `X-API-Key: sk_live_51234567890abcdefghijklmnopqrstuvwxyz`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:         "Docker registry with auth",
			content:      `docker login -u username -p password123 https://registry.example.com`,
			shouldDetect: false, // This detector doesn't match docker login format
		},
		{
			name: "Config file with multiple headers",
			content: `
[api]
auth_header = Authorization: Bearer production_key_xyz789
api_key = X-API-Key: sk_test_abcdef123456
`,
			shouldDetect:  true,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				assert.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect credentials")
				assert.Equal(t, "critical", findings[0].Severity)
			} else {
				assert.Empty(t, findings, "Should not detect credentials")
			}
		})
	}
}
