// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultTokenDetector_Detect(t *testing.T) {
	t.Parallel()

	det := NewVaultTokenDetector()

	tests := []struct {
		name          string
		content       string
		source        string
		wantCount     int
		wantTokenType string
	}{
		{
			name:          "detect hvs. service token",
			content:       "VAULT_TOKEN=hvs.CAESIJXYZabcdefghijklmnop",
			source:        "env:VAULT_TOKEN",
			wantCount:     1,
			wantTokenType: "vault-service-token",
		},
		{
			name:          "detect hvs. token in file",
			content:       "hvs.CAESIJXYZabcdefghijklmnop",
			source:        "file:~/.vault-token",
			wantCount:     1,
			wantTokenType: "vault-service-token",
		},
		{
			name:          "detect legacy s. token",
			content:       "export VAULT_TOKEN=s.ABCDEFGHIJKLMNOPQRSTUVWXyz",
			source:        "file:~/.bashrc",
			wantCount:     1,
			wantTokenType: "vault-legacy-token",
		},
		{
			name:      "detect both hvs. and s. tokens",
			content:   "hvs.CAESIJXYZabcdefghijklmnop\ns.ABCDEFGHIJKLMNOPQRSTUVWXyz",
			source:    "file:~/.vault-token",
			wantCount: 2,
		},
		{
			name:      "no token present",
			content:   "VAULT_ADDR=https://vault.example.com:8200",
			source:    "env:VAULT_ADDR",
			wantCount: 0,
		},
		{
			name:      "s. prefix too short",
			content:   "s.short",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "hvs. prefix too short",
			content:   "hvs.short",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "empty string",
			content:   "",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:          "token in JSON",
			content:       `{"auth":{"client_token":"hvs.CAESIJXYZabcdefghijklmnop"}}`,
			source:        "file:response.json",
			wantCount:     1,
			wantTokenType: "vault-service-token",
		},
		{
			name:          "token in shell history",
			content:       "vault login hvs.CAESIJXYZabcdefghijklmnop",
			source:        "file:~/.bash_history",
			wantCount:     1,
			wantTokenType: "vault-service-token",
		},
		{
			name:      "duplicate tokens deduplicated",
			content:   "hvs.CAESIJXYZabcdefghijklmnop hvs.CAESIJXYZabcdefghijklmnop",
			source:    "file:test",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := det.Detect(tt.content, testCtx(tt.source))
			assert.Len(t, findings, tt.wantCount, "Expected %d findings", tt.wantCount)

			if tt.wantCount > 0 && tt.wantTokenType != "" {
				found := false
				for _, f := range findings {
					if tokenType, ok := f.Metadata["token_type"].(string); ok && tokenType == tt.wantTokenType {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected to find token_type=%s", tt.wantTokenType)
			}

			for i, f := range findings {
				assert.NotEmpty(t, f.ID, "Finding %d missing ID", i)
				assert.NotEmpty(t, f.Severity, "Finding %d missing Severity", i)
				assert.Equal(t, "critical", f.Severity)
				assert.NotEmpty(t, f.Title, "Finding %d missing Title", i)
				assert.NotEmpty(t, f.Message, "Finding %d missing Message", i)
				assert.Equal(t, "vault-token", f.Metadata["detector_name"])
			}
		})
	}
}

func TestVaultTokenDetector_Redact(t *testing.T) {
	t.Parallel()

	det := NewVaultTokenDetector()

	tests := []struct {
		name      string
		content   string
		want      string
		wantCount int
	}{
		{
			name:      "redact hvs. token",
			content:   "VAULT_TOKEN=hvs.CAESIJXYZabcdefghijklmnop",
			want:      "VAULT_TOKEN=[REDACTED-vault-token]",
			wantCount: 1,
		},
		{
			name:      "redact legacy s. token",
			content:   "export VAULT_TOKEN=s.ABCDEFGHIJKLMNOPQRSTUVWXyz",
			want:      "export VAULT_TOKEN=[REDACTED-vault-token]",
			wantCount: 1,
		},
		{
			name:      "no token to redact",
			content:   "VAULT_ADDR=https://vault.example.com",
			want:      "VAULT_ADDR=https://vault.example.com",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, counts := det.Redact(tt.content)
			assert.Equal(t, tt.want, result)

			total := 0
			for _, c := range counts {
				total += c
			}
			assert.Equal(t, tt.wantCount, total)
		})
	}
}

func TestVaultTokenDetector_Name(t *testing.T) {
	t.Parallel()

	det := NewVaultTokenDetector()
	require.Equal(t, "vault-token", det.Name())
}
