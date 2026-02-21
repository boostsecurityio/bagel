// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package scrubber

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScrubContent_Patterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantLabel string
		wantOut   string
	}{
		// 1. SSH private key
		{
			name:      "ssh private key RSA",
			input:     "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH9+12345678901234567890ABCDEFGH=\n-----END RSA PRIVATE KEY-----",
			wantLabel: "REDACTED-ssh-private-key",
			wantOut:   "[REDACTED-ssh-private-key]",
		},
		{
			name:      "ssh private key OPENSSH",
			input:     "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA+/==\n-----END OPENSSH PRIVATE KEY-----",
			wantLabel: "REDACTED-ssh-private-key",
			wantOut:   "[REDACTED-ssh-private-key]",
		},
		// 2. Bearer + JWT
		{
			name:      "bearer jwt",
			input:     "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantLabel: "REDACTED-jwt",
			wantOut:   "Bearer [REDACTED-jwt]",
		},
		// 3. Bearer + non-JWT token
		{
			name:      "bearer generic token",
			input:     "Bearer some-opaque-token-value-that-is-long-enough-here",
			wantLabel: "REDACTED-bearer-token",
			wantOut:   "Bearer [REDACTED-bearer-token]",
		},
		// 4. Basic auth header
		{
			name:      "basic auth header",
			input:     "Basic YWRtaW46cGFzc3dvcmQxMjM0NTY3OA==",
			wantLabel: "REDACTED-basic-auth",
			wantOut:   "Basic [REDACTED-basic-auth]",
		},
		// 5. Anthropic API key
		{
			name:      "anthropic key",
			input:     "sk-ant-api03-abcdefghij1234567890-ABCDE",
			wantLabel: "REDACTED-anthropic-key",
			wantOut:   "[REDACTED-anthropic-key]",
		},
		// 6. OpenAI API key (new format)
		{
			name:      "openai key sk-proj",
			input:     "sk-proj-abcdefghij1234567890-ABC",
			wantLabel: "REDACTED-openai-key",
			wantOut:   "[REDACTED-openai-key]",
		},
		// 7. Generic OpenAI key (older)
		{
			name:      "openai key generic sk-",
			input:     "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789",
			wantLabel: "REDACTED-openai-key",
			wantOut:   "[REDACTED-openai-key]",
		},
		// 8. AWS access key (AKIA)
		{
			name:      "aws access key AKIA",
			input:     "AKIAIOSFODNN7EXAMPLE",
			wantLabel: "REDACTED-aws-access-key",
			wantOut:   "[REDACTED-aws-access-key]",
		},
		// 9. AWS STS key (ASIA)
		{
			name:      "aws sts key ASIA",
			input:     "ASIA1234567890ABCDEF",
			wantLabel: "REDACTED-aws-sts-key",
			wantOut:   "[REDACTED-aws-sts-key]",
		},
		// 10. AWS session token (labeled)
		{
			name:      "aws session token labeled",
			input:     `aws_session_token = ` + longBase64(120),
			wantLabel: "REDACTED-aws-session-token",
			wantOut:   `aws_session_token = [REDACTED-aws-session-token]`,
		},
		// 11. AWS STS session token (label-free)
		{
			name:      "aws sts session token prefix",
			input:     "IQoJb3JpZ2lu" + longBase64(120),
			wantLabel: "REDACTED-aws-session-token",
			wantOut:   "[REDACTED-aws-session-token]",
		},
		// 12. AWS secret access key (labeled)
		{
			name:      "aws secret key labeled",
			input:     `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
			wantLabel: "REDACTED-aws-secret-key",
			wantOut:   `aws_secret_access_key = [REDACTED-aws-secret-key]`,
		},
		// 13. Splunk session
		{
			name:      "splunk session token",
			input:     "splunkd_" + repeatChar('a', 32),
			wantLabel: "REDACTED-splunk-session",
			wantOut:   "[REDACTED-splunk-session]",
		},
		// 14. GitHub PAT
		{
			name:      "github classic pat",
			input:     "ghp_" + repeatChar('A', 36),
			wantLabel: "REDACTED-github-pat",
			wantOut:   "[REDACTED-github-pat]",
		},
		// 15. GitHub OAuth
		{
			name:      "github oauth token",
			input:     "gho_" + repeatChar('B', 36),
			wantLabel: "REDACTED-github-oauth",
			wantOut:   "[REDACTED-github-oauth]",
		},
		// 16. GitHub user token
		{
			name:      "github user token",
			input:     "ghu_" + repeatChar('C', 36),
			wantLabel: "REDACTED-github-user",
			wantOut:   "[REDACTED-github-user]",
		},
		// 17. GitHub app token
		{
			name:      "github app token",
			input:     "ghs_" + repeatChar('D', 36),
			wantLabel: "REDACTED-github-app",
			wantOut:   "[REDACTED-github-app]",
		},
		// 18. GitHub fine-grained PAT
		{
			name:      "github fine-grained pat",
			input:     "github_pat_" + repeatChar('E', 22),
			wantLabel: "REDACTED-github-fine-pat",
			wantOut:   "[REDACTED-github-fine-pat]",
		},
		// 19. NPM token
		{
			name:      "npm token",
			input:     "npm_" + repeatChar('F', 36),
			wantLabel: "REDACTED-npm-token",
			wantOut:   "[REDACTED-npm-token]",
		},
		// 20. Basic auth in URLs
		{
			name:      "basic auth in url",
			input:     "https://admin:s3cretP4ss@example.com/api",
			wantLabel: "REDACTED-basic-auth",
			wantOut:   "https://[REDACTED-basic-auth]@example.com/api",
		},
		// 21. Standalone JWT
		{
			name:      "standalone jwt",
			input:     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantLabel: "REDACTED-jwt",
			wantOut:   "[REDACTED-jwt]",
		},
		// 22. Azure storage key
		{
			name:      "azure storage key",
			input:     `AccountKey=` + longBase64(86) + "==",
			wantLabel: "REDACTED-azure-storage-key",
			wantOut:   `AccountKey=[REDACTED-azure-storage-key]`,
		},
		// 23. GCP API key
		{
			name:      "gcp api key",
			input:     "AIzaSyA" + repeatChar('x', 32),
			wantLabel: "REDACTED-gcp-api-key",
			wantOut:   "[REDACTED-gcp-api-key]",
		},
		// 24. API key header
		{
			name:      "x-api-key header",
			input:     `X-API-Key: ` + repeatChar('z', 40),
			wantLabel: "REDACTED-api-key-header",
			wantOut:   "[REDACTED-api-key-header]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := ScrubContent(tt.input)
			assert.Equal(t, tt.wantOut, out, "scrubbed output mismatch")
			assert.Greater(t, counts[tt.wantLabel], 0, "expected label %s in counts", tt.wantLabel)
		})
	}
}

func TestScrubContent_NegativeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "short string", input: "hello world"},
		{name: "sk- too short", input: "sk-abc123"},
		{name: "AKIA too short", input: "AKIA123"},
		{name: "ghp_ too short", input: "ghp_short"},
		{name: "npm_ too short", input: "npm_short"},
		{name: "not a jwt", input: "eyJnotvalid"},
		{name: "normal url no creds", input: "https://example.com/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, counts := ScrubContent(tt.input)
			assert.Equal(t, tt.input, out, "should not modify non-matching input")
			assert.Empty(t, counts, "should have zero counts")
		})
	}
}

func TestScrubContent_OrderingBearerJWT(t *testing.T) {
	t.Parallel()

	// Bearer + JWT should match as "Bearer [REDACTED-jwt]", not as
	// "Bearer [REDACTED-bearer-token]" followed by standalone JWT redaction.
	input := "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	out, counts := ScrubContent(input)

	assert.Equal(t, "Bearer [REDACTED-jwt]", out)
	assert.Equal(t, 1, counts["REDACTED-jwt"])
	assert.Zero(t, counts["REDACTED-bearer-token"], "bearer-token should not match when JWT matches first")
}

func TestScrubContent_AnthropicBeforeGenericSK(t *testing.T) {
	t.Parallel()

	// sk-ant- should match as anthropic, not generic openai
	input := "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
	out, _ := ScrubContent(input)
	assert.Equal(t, "[REDACTED-anthropic-key]", out)
}

func TestScrubContent_MultipleSecrets(t *testing.T) {
	t.Parallel()

	input := "key1=AKIAIOSFODNN7EXAMPLE key2=ghp_" + repeatChar('X', 36)
	out, counts := ScrubContent(input)

	assert.Contains(t, out, "[REDACTED-aws-access-key]")
	assert.Contains(t, out, "[REDACTED-github-pat]")
	assert.Equal(t, 1, counts["REDACTED-aws-access-key"])
	assert.Equal(t, 1, counts["REDACTED-github-pat"])
}

func TestScrubContent_JSONEmbedded(t *testing.T) {
	t.Parallel()

	// Secrets often appear inside JSON strings in JSONL logs
	input := `{"token":"ghp_` + repeatChar('Z', 36) + `","user":"alice"}`
	out, counts := ScrubContent(input)

	assert.Contains(t, out, "[REDACTED-github-pat]")
	assert.Equal(t, 1, counts["REDACTED-github-pat"])
	assert.Contains(t, out, `"user":"alice"`)
}

func TestScrubFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	content := `{"key":"AKIAIOSFODNN7EXAMPLE","data":"safe"}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	changed, counts, err := ScrubFile(path)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, 1, counts["REDACTED-aws-access-key"])

	// Verify file was actually modified
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[REDACTED-aws-access-key]")
	assert.NotContains(t, string(data), "AKIAIOSFODNN7EXAMPLE")
}

func TestScrubFile_NoChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "clean.jsonl")

	require.NoError(t, os.WriteFile(path, []byte(`{"safe":"data"}`), 0600))

	changed, counts, err := ScrubFile(path)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Empty(t, counts)
}

func TestScrubFile_PreservesPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "perms.jsonl")

	require.NoError(t, os.WriteFile(path, []byte("AKIAIOSFODNN7EXAMPLE"), 0640))

	_, _, err := ScrubFile(path)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
}

func TestFindEligibleFiles(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude", "projects", "test-project")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	// Create an old file (should be found)
	oldFile := filepath.Join(claudeDir, "session.jsonl")
	require.NoError(t, os.WriteFile(oldFile, []byte("data"), 0600))
	oldTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(oldFile, oldTime, oldTime))

	// Create a recent file (should be skipped with default 60min grace)
	newFile := filepath.Join(claudeDir, "active.jsonl")
	require.NoError(t, os.WriteFile(newFile, []byte("data"), 0600))

	ctx := zerolog.Nop().WithContext(context.Background())
	files, err := FindEligibleFiles(ctx, 60)
	require.NoError(t, err)

	assert.Contains(t, files, oldFile, "old file should be eligible")
	assert.NotContains(t, files, newFile, "recent file should be skipped")
}

func TestFindEligibleFiles_GraceZero(t *testing.T) {
	// Cannot use t.Parallel() with t.Setenv
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude", "projects", "test")
	require.NoError(t, os.MkdirAll(claudeDir, 0700))

	f := filepath.Join(claudeDir, "session.jsonl")
	require.NoError(t, os.WriteFile(f, []byte("data"), 0600))

	ctx := zerolog.Nop().WithContext(context.Background())
	files, err := FindEligibleFiles(ctx, 0)
	require.NoError(t, err)
	assert.Contains(t, files, f, "grace=0 should include all files")
}

func TestRun_DryRun(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	content := `{"key":"AKIAIOSFODNN7EXAMPLE"}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	ctx := zerolog.Nop().WithContext(context.Background())
	result, err := Run(ctx, RunInput{
		Confirm: false,
		File:    path,
	})
	require.NoError(t, err)

	assert.Equal(t, 1, result.FilesScanned)
	assert.Equal(t, 1, result.FilesModified)
	assert.Equal(t, 1, result.Redactions)

	// Verify file was NOT modified (dry run)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, string(data), "dry run should not modify files")
}

func TestRun_Confirm(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")
	content := `{"key":"AKIAIOSFODNN7EXAMPLE"}`
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	ctx := zerolog.Nop().WithContext(context.Background())
	result, err := Run(ctx, RunInput{
		Confirm: true,
		File:    path,
	})
	require.NoError(t, err)

	assert.Equal(t, 1, result.FilesModified)
	assert.Equal(t, 1, result.Redactions)

	// Verify file WAS modified
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), "[REDACTED-aws-access-key]")
}

func TestRun_FileNotFound(t *testing.T) {
	t.Parallel()

	ctx := zerolog.Nop().WithContext(context.Background())
	_, err := Run(ctx, RunInput{
		File: "/nonexistent/path.jsonl",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}

// -- helpers --

func repeatChar(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func longBase64(n int) string {
	// Produces a string of valid base64 characters of length n
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[i%len(chars)]
	}
	return string(b)
}
