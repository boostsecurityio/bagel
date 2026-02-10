// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWTDetector_Detect(t *testing.T) {
	detector := NewJWTDetector()

	tests := []struct {
		name          string
		content       string
		source        string
		wantCount     int
		wantTokenType string
	}{
		{
			name:          "detect regular JWT",
			content:       "AUTH_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30",
			source:        "env:AUTH_TOKEN",
			wantCount:     1,
			wantTokenType: "jwt-token",
		},
		{
			name:          "detect encrypted JWT (JWE)",
			content:       "\"id_token\": \"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.O01BFr_XxGzKEUb_Z9vQOW3DX2cQFxojrRy2JyM5_nqKnrpAa0rvcPI_ViT2PdPRogBwjHGRDM2uNLd1BberKQlaZYuqPGXnpzDQjosF0tQlgdtY3uEZUMT-9WPP8jCxxQg0AGIm4abkp1cgzAWBQzm1QYL8fwaz16MS48ExRz41dLhA0aEWE4e7TYzjrfaK8M4wIUlQCFIl-wS1N3U8W2XeUc9MLYGmHft_Rd9KJs1c-9KKdUQf6tEzJ92TGEC7TRZX4hGdtszIq3GGGBQaW8P9jPozqaDdrikF18D0btRHNf3_57sR_CPEGYX0O4mY775CLWqB4Y1adNn-fZ0xoA.ln7IYZDF9TdBIK6i.ZhQ3Q5TY827KFQw8DdRRzQVJVFdIE03B6AxMNZ1sQIjlUB4QUxg-UYqjPJESPUmFsODeshGWLa5t4tUri5j6uC4mFDbkbemPmNKIQiY5m8yc.5KKhrggMRm7ydVRQKJaT0g\"",
			source:        "file:oauth_creds.json",
			wantCount:     1,
			wantTokenType: "jwe-token",
		},
		{
			name:      "no token present",
			content:   "SOME_VAR=some_value",
			source:    "env:SOME_VAR",
			wantCount: 0,
		},
		{
			name:      "detect multiple types",
			content:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV3 and eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.O01BFr_XxGzKEUb_Z9vQOW3DX2cQFxojrRy2JyM5_nqKnrpAa0rvcPI_ViT2PdPRogBwjHGRDM2uNLd1BberKQlaZYuqPGXnpzDQjosF0tQlgdtY3uEZUMT-9WPP8jCxxQg0AGIm4abkp1cgzAWBQzm1QYL8fwaz16MS48ExRz41dLhA0aEWE4e7TYzjrfaK8M4wIUlQCFIl-wS1N3U8W2XeUc9MLYGmHft_Rd9KJs1c-9KKdUQf6tEzJ92TGEC7TRZX4hGdtszIq3GGGBQaW8P9jPozqaDdrikF18D0btRHNf3_57sR_CPEGYX0O4mY775CLWqB4Y1adNn-fZ0xoA.ln7IYZDF9TdBIK6i.ZhQ3Q5TY827KFQw8DdRRzQVJVFdIE03B6AxMNZ1sQIjlUB4QUxg-UYqjPJESPUmFsODeshGWLa5t4tUri5j6uC4mFDbkbemPmNKIQiY5m8yc.5KKhrggMRm7ydVRQKJaT0g",
			source:    "file:config.txt",
			wantCount: 2,
		},
		{
			name:      "multiple tokens of same type",
			content:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30\neyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.ANCf_8p1AE4ZQs7QuqGAyyfTEgYrKSjKWkhBk5cIn1_2QVr2jEjmM-1tu7EgnyOf_fAsvdFXva8Sv05iTGzETg",
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

func TestJWTDetector_Name(t *testing.T) {
	detector := NewJWTDetector()
	assert.Equal(t, "jwt", detector.Name())
}
