// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package scrubber

import (
	"regexp"
	"strings"
)

// Pattern holds a compiled regex, its replacement string, and cheap
// prefix strings used to skip the regex entirely when no prefix
// appears in the content.
type Pattern struct {
	Regex       *regexp.Regexp
	Replacement string
	Label       string
	Prefixes    []string // at least one must appear for the regex to match
}

// containsAny returns true if content contains at least one of the prefixes.
func containsAny(content string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}

// quickPrefixes is the deduplicated union of all pattern prefixes.
// If none appear in a file, no pattern can match and the file can
// be skipped without running any regex.
var quickPrefixes = buildQuickPrefixes()

func buildQuickPrefixes() []string {
	seen := make(map[string]bool)
	for _, p := range Patterns() {
		for _, pfx := range p.Prefixes {
			seen[pfx] = true
		}
	}
	out := make([]string, 0, len(seen))
	for pfx := range seen {
		out = append(out, pfx)
	}
	return out
}

// MightContainSecrets does a fast string-prefix scan. Returns false
// only when it is certain no pattern can match, allowing callers to
// skip the expensive regex pass entirely.
func MightContainSecrets(content string) bool {
	return containsAny(content, quickPrefixes)
}

// Patterns returns the ordered list of credential-scrubbing patterns.
// Order matters: more specific patterns must come before general ones.
//
//nolint:funlen // pattern table is intentionally long
func Patterns() []Pattern {
	return []Pattern{
		// 1. SSH private keys (multiline-safe for JSON-escaped \n)
		{
			Regex: regexp.MustCompile(
				`-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----` +
					`[A-Za-z0-9+/=\s\\n]{20,}` +
					`-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE KEY-----`),
			Replacement: `[REDACTED-ssh-private-key]`,
			Label:       "REDACTED-ssh-private-key",
			Prefixes:    []string{"-----BEGIN"},
		},
		// 2. Bearer + JWT combined
		{
			Regex: regexp.MustCompile(
				`Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Replacement: `Bearer [REDACTED-jwt]`,
			Label:       "REDACTED-jwt",
			Prefixes:    []string{"Bearer"},
		},
		// 3. Bearer + non-JWT token
		{
			Regex: regexp.MustCompile(
				`Bearer\s+[A-Za-z0-9_.\-/+=]{20,}`),
			Replacement: `Bearer [REDACTED-bearer-token]`,
			Label:       "REDACTED-bearer-token",
			Prefixes:    []string{"Bearer"},
		},
		// 4. Basic auth header
		{
			Regex: regexp.MustCompile(
				`Basic\s+[A-Za-z0-9+/=]{20,}`),
			Replacement: `Basic [REDACTED-basic-auth]`,
			Label:       "REDACTED-basic-auth",
			Prefixes:    []string{"Basic"},
		},
		// 5. Anthropic API key (before generic sk-)
		{
			Regex:       regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`),
			Replacement: `[REDACTED-anthropic-key]`,
			Label:       "REDACTED-anthropic-key",
			Prefixes:    []string{"sk-ant-"},
		},
		// 6. OpenAI API key (new format)
		{
			Regex:       regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{20,}`),
			Replacement: `[REDACTED-openai-key]`,
			Label:       "REDACTED-openai-key",
			Prefixes:    []string{"sk-proj-"},
		},
		// 7. Generic OpenAI key (older format)
		{
			Regex:       regexp.MustCompile(`sk-[A-Za-z0-9]{40,}`),
			Replacement: `[REDACTED-openai-key]`,
			Label:       "REDACTED-openai-key",
			Prefixes:    []string{"sk-"},
		},
		// 8. AWS access key ID (long-term)
		{
			Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Replacement: `[REDACTED-aws-access-key]`,
			Label:       "REDACTED-aws-access-key",
			Prefixes:    []string{"AKIA"},
		},
		// 9. AWS STS temporary credentials
		{
			Regex:       regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
			Replacement: `[REDACTED-aws-sts-key]`,
			Label:       "REDACTED-aws-sts-key",
			Prefixes:    []string{"ASIA"},
		},
		// 10. AWS session token (with label)
		{
			Regex: regexp.MustCompile(
				`((?:aws_session_token|AWS_SESSION_TOKEN|SessionToken)["\s:=]+)[A-Za-z0-9+/=]{100,}`),
			Replacement: `${1}[REDACTED-aws-session-token]`,
			Label:       "REDACTED-aws-session-token",
			Prefixes:    []string{"aws_session_token", "AWS_SESSION_TOKEN", "SessionToken"},
		},
		// 11. AWS STS session token (label-free, base64 prefix)
		{
			Regex:       regexp.MustCompile(`IQoJb3JpZ2lu[A-Za-z0-9+/=]{100,}`),
			Replacement: `[REDACTED-aws-session-token]`,
			Label:       "REDACTED-aws-session-token",
			Prefixes:    []string{"IQoJb3JpZ2lu"},
		},
		// 12. AWS secret access key (with label)
		{
			Regex: regexp.MustCompile(
				`((?:aws_secret_access_key|secret_access_key|SecretAccessKey)["\s:=]+)[A-Za-z0-9+/]{40}`),
			Replacement: `${1}[REDACTED-aws-secret-key]`,
			Label:       "REDACTED-aws-secret-key",
			Prefixes:    []string{"aws_secret_access_key", "secret_access_key", "SecretAccessKey"},
		},
		// 13. Splunk session tokens
		{
			Regex:       regexp.MustCompile(`splunkd_[A-Za-z0-9]{32,}`),
			Replacement: `[REDACTED-splunk-session]`,
			Label:       "REDACTED-splunk-session",
			Prefixes:    []string{"splunkd_"},
		},
		// 14. GitHub PAT (classic)
		{
			Regex:       regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,}`),
			Replacement: `[REDACTED-github-pat]`,
			Label:       "REDACTED-github-pat",
			Prefixes:    []string{"ghp_"},
		},
		// 15. GitHub OAuth token
		{
			Regex:       regexp.MustCompile(`gho_[A-Za-z0-9_]{36,}`),
			Replacement: `[REDACTED-github-oauth]`,
			Label:       "REDACTED-github-oauth",
			Prefixes:    []string{"gho_"},
		},
		// 16. GitHub user token
		{
			Regex:       regexp.MustCompile(`ghu_[A-Za-z0-9_]{36,}`),
			Replacement: `[REDACTED-github-user]`,
			Label:       "REDACTED-github-user",
			Prefixes:    []string{"ghu_"},
		},
		// 17. GitHub app token
		{
			Regex:       regexp.MustCompile(`ghs_[A-Za-z0-9_]{36,}`),
			Replacement: `[REDACTED-github-app]`,
			Label:       "REDACTED-github-app",
			Prefixes:    []string{"ghs_"},
		},
		// 18. GitHub fine-grained PAT
		{
			Regex:       regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
			Replacement: `[REDACTED-github-fine-pat]`,
			Label:       "REDACTED-github-fine-pat",
			Prefixes:    []string{"github_pat_"},
		},
		// 19. NPM token
		{
			Regex:       regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`),
			Replacement: `[REDACTED-npm-token]`,
			Label:       "REDACTED-npm-token",
			Prefixes:    []string{"npm_"},
		},
		// 20. Basic auth in URLs (preserve scheme and @)
		{
			Regex:       regexp.MustCompile(`(https?://)[^:"\s\\]+:[^@"\s\\]+(@)`),
			Replacement: `${1}[REDACTED-basic-auth]${2}`,
			Label:       "REDACTED-basic-auth",
			Prefixes:    []string{"://"}, // @-sign required by regex but :// is the cheaper check
		},
		// 21. Standalone JWT (after Bearer patterns to avoid double-match)
		{
			Regex: regexp.MustCompile(
				`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Replacement: `[REDACTED-jwt]`,
			Label:       "REDACTED-jwt",
			Prefixes:    []string{"eyJ"},
		},
		// 22. Azure storage key (with label)
		{
			Regex: regexp.MustCompile(
				`((?:AccountKey|storage_key|StorageKey)["\s:=]+)[A-Za-z0-9+/]{86}==`),
			Replacement: `${1}[REDACTED-azure-storage-key]`,
			Label:       "REDACTED-azure-storage-key",
			Prefixes:    []string{"AccountKey", "storage_key", "StorageKey"},
		},
		// 23. GCP API key
		{
			Regex:       regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
			Replacement: `[REDACTED-gcp-api-key]`,
			Label:       "REDACTED-gcp-api-key",
			Prefixes:    []string{"AIza"},
		},
		// 24. Authorization header with API key
		{
			Regex: regexp.MustCompile(
				`(?:X-API-Key|x-api-key|Authorization)[":\s]+[A-Za-z0-9_.\-/+=]{30,}`),
			Replacement: `[REDACTED-api-key-header]`,
			Label:       "REDACTED-api-key-header",
			Prefixes:    []string{"X-API-Key", "x-api-key", "Authorization"},
		},
	}
}
