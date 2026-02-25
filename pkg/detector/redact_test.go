// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSSHPrivateKeyDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewSSHPrivateKeyDetector()

	input := "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH9+12345678901234567890ABCDEFGH=\n-----END RSA PRIVATE KEY-----"
	out, counts := d.Redact(input)
	assert.Equal(t, "[REDACTED-ssh-private-key]", out)
	assert.Equal(t, 1, counts["REDACTED-ssh-private-key"])
}

func TestSSHPrivateKeyDetector_Redact_NoMatch(t *testing.T) {
	t.Parallel()
	d := NewSSHPrivateKeyDetector()

	out, counts := d.Redact("no keys here")
	assert.Equal(t, "no keys here", out)
	assert.Empty(t, counts)
}

func TestGitHubTokenDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewGitHubPATDetector()

	tests := []struct {
		name  string
		input string
		want  string
		label string
	}{
		{"classic pat", "ghp_" + repeat('A', 36), "[REDACTED-github-pat]", "REDACTED-github-pat"},
		{"oauth", "gho_" + repeat('B', 36), "[REDACTED-github-oauth]", "REDACTED-github-oauth"},
		{"user", "ghu_" + repeat('C', 36), "[REDACTED-github-user]", "REDACTED-github-user"},
		{"app", "ghs_" + repeat('D', 36), "[REDACTED-github-app]", "REDACTED-github-app"},
		{"fine-grained", "github_pat_" + repeat('E', 22), "[REDACTED-github-fine-pat]", "REDACTED-github-fine-pat"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := d.Redact(tt.input)
			assert.Equal(t, tt.want, out)
			assert.Equal(t, 1, counts[tt.label])
		})
	}
}

func TestNPMTokenDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewNPMTokenDetector()

	out, counts := d.Redact("npm_" + repeat('F', 36))
	assert.Equal(t, "[REDACTED-npm-token]", out)
	assert.Equal(t, 1, counts["REDACTED-npm-token"])
}

func TestAIServiceDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewAIServiceDetector()

	tests := []struct {
		name  string
		input string
		want  string
		label string
	}{
		{
			"anthropic",
			"sk-ant-api03-abcdefghij1234567890-ABCDE",
			"[REDACTED-anthropic-key]",
			"REDACTED-anthropic-key",
		},
		{
			"openai sk-proj",
			"sk-proj-abcdefghij1234567890-ABC",
			"[REDACTED-openai-key]",
			"REDACTED-openai-key",
		},
		{
			"openai generic",
			"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789",
			"[REDACTED-openai-key]",
			"REDACTED-openai-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := d.Redact(tt.input)
			assert.Equal(t, tt.want, out)
			assert.Positive(t, counts[tt.label])
		})
	}
}

func TestAIServiceDetector_Redact_AnthropicBeforeGeneric(t *testing.T) {
	t.Parallel()
	d := NewAIServiceDetector()

	// sk-ant- must not match the generic sk- pattern
	input := "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
	out, _ := d.Redact(input)
	assert.Equal(t, "[REDACTED-anthropic-key]", out)
}

func TestHTTPAuthDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewHTTPAuthDetector()

	tests := []struct {
		name  string
		input string
		want  string
		label string
	}{
		{
			"bearer jwt",
			"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			"Bearer [REDACTED-jwt]",
			"REDACTED-jwt",
		},
		{
			"bearer generic",
			"Bearer some-opaque-token-value-that-is-long-enough-here",
			"Bearer [REDACTED-bearer-token]",
			"REDACTED-bearer-token",
		},
		{
			"basic auth",
			"Basic YWRtaW46cGFzc3dvcmQxMjM0NTY3OA==",
			"Basic [REDACTED-basic-auth]",
			"REDACTED-basic-auth",
		},
		{
			"url auth",
			"https://admin:s3cretP4ss@example.com/api",
			"https://[REDACTED-basic-auth]@example.com/api",
			"REDACTED-basic-auth",
		},
		{
			"api key header",
			"X-API-Key: " + repeat('z', 40),
			"[REDACTED-api-key-header]",
			"REDACTED-api-key-header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := d.Redact(tt.input)
			assert.Equal(t, tt.want, out)
			assert.Positive(t, counts[tt.label])
		})
	}
}

func TestCloudCredentialsDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewCloudCredentialsDetector()

	tests := []struct {
		name  string
		input string
		want  string
		label string
	}{
		{"aws akia", "AKIAIOSFODNN7EXAMPLE", "[REDACTED-aws-access-key]", "REDACTED-aws-access-key"},
		{"aws asia", "ASIA1234567890ABCDEF", "[REDACTED-aws-sts-key]", "REDACTED-aws-sts-key"},
		{"gcp", "AIzaSyA" + repeat('x', 32), "[REDACTED-gcp-api-key]", "REDACTED-gcp-api-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := d.Redact(tt.input)
			assert.Equal(t, tt.want, out)
			assert.Equal(t, 1, counts[tt.label])
		})
	}
}

func TestCloudCredentialsDetector_Redact_AWSSessionToken(t *testing.T) {
	t.Parallel()
	d := NewCloudCredentialsDetector()

	b64 := longBase64(120)
	input := "aws_session_token = " + b64
	out, counts := d.Redact(input)
	assert.Equal(t, "aws_session_token = [REDACTED-aws-session-token]", out)
	assert.Positive(t, counts["REDACTED-aws-session-token"])
}

func TestCloudCredentialsDetector_Redact_AWSSecretKey(t *testing.T) {
	t.Parallel()
	d := NewCloudCredentialsDetector()

	input := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	out, counts := d.Redact(input)
	assert.Equal(t, "aws_secret_access_key = [REDACTED-aws-secret-key]", out)
	assert.Equal(t, 1, counts["REDACTED-aws-secret-key"])
}

func TestJWTDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewJWTDetector()

	input := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	out, counts := d.Redact(input)
	assert.Equal(t, "[REDACTED-jwt]", out)
	assert.Equal(t, 1, counts["REDACTED-jwt"])
}

func TestSplunkTokenDetector_Redact(t *testing.T) {
	t.Parallel()
	d := NewSplunkTokenDetector()

	input := "splunkd_" + repeat('a', 32)
	out, counts := d.Redact(input)
	assert.Equal(t, "[REDACTED-splunk-session]", out)
	assert.Equal(t, 1, counts["REDACTED-splunk-session"])
}

func TestGenericAPIKeyDetector_Redact_NoPatterns(t *testing.T) {
	t.Parallel()
	d := NewGenericAPIKeyDetector()

	// GenericAPIKeyDetector has no redaction patterns (header redaction is
	// in HTTPAuthDetector), so Redact should be a no-op.
	input := "some random content"
	out, counts := d.Redact(input)
	assert.Equal(t, input, out)
	assert.Empty(t, counts)
}

func TestRedactAll_RegistryOrdering(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.Register(NewHTTPAuthDetector())
	registry.Register(NewJWTDetector())

	// Bearer+JWT should be handled by HTTPAuth, standalone JWT should not
	// double-match the already-redacted content
	input := "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	out, counts := registry.RedactAll(input)
	assert.Equal(t, "Bearer [REDACTED-jwt]", out)
	assert.Equal(t, 1, counts["REDACTED-jwt"])
}

// -- helpers --

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func longBase64(n int) string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[i%len(chars)]
	}
	return string(b)
}
