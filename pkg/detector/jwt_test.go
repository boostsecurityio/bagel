// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeJWT crafts a JWS with the given claims. The signature segment is
// arbitrary — classification is signature-blind — but must satisfy the
// detector regex's length requirement.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + ".signature_placeholder_long_enough_to_match"
}

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

// assertStableJWS asserts that the existing JWT finding ID/Title/token_type
// contract is preserved. Classification of the JWS into a specialized
// subtype (K8s SA, GitHub OIDC, etc.) must surface only in metadata via
// token_subtype + extras — never by changing the existing ID, Title, or
// base token_type.
func assertStableJWS(t *testing.T, f models.Finding) {
	t.Helper()
	assert.Equal(t, "jwt-jwt-token", f.ID, "ID must stay stable for JWS")
	assert.Equal(t, "JWT Token Detected", f.Title, "Title must stay stable for JWS")
	assert.Equal(t, "jwt-token", f.Metadata["token_type"], "token_type must stay stable for JWS")
}

func TestJWTDetector_Classify_KubernetesServiceAccount(t *testing.T) {
	det := NewJWTDetector()

	t.Run("bound token with kubernetes.io claim", func(t *testing.T) {
		token := makeJWT(t, map[string]any{
			"iss": "https://kubernetes.default.svc.cluster.local",
			"sub": "system:serviceaccount:kube-system:my-sa",
			"aud": []string{"https://kubernetes.default.svc.cluster.local"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"kubernetes.io": map[string]any{
				"namespace": "kube-system",
				"serviceaccount": map[string]any{
					"name": "my-sa",
					"uid":  "11111111-1111-1111-1111-111111111111",
				},
			},
		})

		findings := det.Detect(token, testCtx("file:token"))
		require.Len(t, findings, 1)
		f := findings[0]
		assertStableJWS(t, f)
		assert.Equal(t, "jwt-kubernetes-service-account", f.Metadata["token_subtype"])
		assert.Equal(t, "kube-system", f.Metadata["k8s_namespace"])
		assert.Equal(t, "my-sa", f.Metadata["k8s_serviceaccount"])
		assert.Equal(t, false, f.Metadata["expired"])
	})

	t.Run("legacy token recognized via sub prefix only", func(t *testing.T) {
		token := makeJWT(t, map[string]any{
			"iss": "kubernetes/serviceaccount",
			"sub": "system:serviceaccount:default:default",
		})
		findings := det.Detect(token, testCtx("file:legacy"))
		require.Len(t, findings, 1)
		assertStableJWS(t, findings[0])
		assert.Equal(t, "jwt-kubernetes-service-account", findings[0].Metadata["token_subtype"])
	})
}

func TestJWTDetector_Classify_GitHubActionsOIDC(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss":        "https://token.actions.githubusercontent.com",
		"sub":        "repo:boostsecurityio/bagel:ref:refs/heads/main",
		"aud":        "sigstore",
		"repository": "boostsecurityio/bagel",
		"workflow":   "CI",
		"ref":        "refs/heads/main",
		"actor":      "amfortin",
	})

	findings := det.Detect(token, testCtx("env:ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	require.Len(t, findings, 1)
	f := findings[0]
	assertStableJWS(t, f)
	assert.Equal(t, "jwt-github-actions-oidc", f.Metadata["token_subtype"])
	assert.Equal(t, "boostsecurityio/bagel", f.Metadata["github_repository"])
	assert.Equal(t, "CI", f.Metadata["github_workflow"])
	assert.Equal(t, "refs/heads/main", f.Metadata["github_ref"])
	assert.Equal(t, "amfortin", f.Metadata["github_actor"])
}

func TestJWTDetector_Classify_AWSIRSA(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss": "https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789",
		"sub": "system:serviceaccount:default:my-app",
		"aud": "sts.amazonaws.com",
	})

	findings := det.Detect(token, testCtx("file:web-identity"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	// K8s SA prefix on sub still classifies first — IRSA tokens are
	// projected K8s SA tokens. This is the intended ordering.
	assert.Equal(t, "jwt-kubernetes-service-account", findings[0].Metadata["token_subtype"])

	tokenNonK8s := makeJWT(t, map[string]any{
		"iss": "https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF0123456789",
		"sub": "arn:aws:iam::123456789012:role/my-role",
		"aud": "sts.amazonaws.com",
	})
	findings = det.Detect(tokenNonK8s, testCtx("file:web-identity"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	assert.Equal(t, "jwt-aws-irsa", findings[0].Metadata["token_subtype"])
	assert.Contains(t, findings[0].Metadata["oidc_issuer"], "oidc.eks.us-east-1.amazonaws.com")
}

func TestJWTDetector_Classify_AzureAD(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss":   "https://sts.windows.net/00000000-0000-0000-0000-000000000000/",
		"tid":   "00000000-0000-0000-0000-000000000000",
		"appid": "11111111-1111-1111-1111-111111111111",
	})
	findings := det.Detect(token, testCtx("file:azure-token"))
	require.Len(t, findings, 1)
	f := findings[0]
	assertStableJWS(t, f)
	assert.Equal(t, "jwt-azure-ad", f.Metadata["token_subtype"])
	assert.Equal(t, "00000000-0000-0000-0000-000000000000", f.Metadata["azure_tenant"])
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", f.Metadata["azure_app_id"])
}

func TestJWTDetector_Classify_GoogleIDToken(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss": "https://accounts.google.com",
		"sub": "1234567890",
		"aud": "client-id.apps.googleusercontent.com",
	})
	findings := det.Detect(token, testCtx("file:google-id"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	assert.Equal(t, "jwt-gcp-id-token", findings[0].Metadata["token_subtype"])
}

func TestJWTDetector_Classify_GCPServiceAccount(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss": "my-sa@my-project.iam.gserviceaccount.com",
		"sub": "my-sa@my-project.iam.gserviceaccount.com",
		"aud": "https://www.googleapis.com/oauth2/v4/token",
	})
	findings := det.Detect(token, testCtx("file:gcp-sa-jwt"))
	require.Len(t, findings, 1)
	f := findings[0]
	assertStableJWS(t, f)
	assert.Equal(t, "jwt-gcp-service-account", f.Metadata["token_subtype"])
	assert.Equal(t, "my-sa@my-project.iam.gserviceaccount.com", f.Metadata["gcp_service_account"])
}

func TestJWTDetector_Classify_VaultAud(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"iss": "https://example.idp.com",
		"sub": "user@example.com",
		"aud": []string{"vault.example.com"},
	})
	findings := det.Detect(token, testCtx("file:vault-jwt"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	assert.Equal(t, "jwt-vault-auth", findings[0].Metadata["token_subtype"])
}

func TestJWTDetector_Expired(t *testing.T) {
	det := NewJWTDetector()
	token := makeJWT(t, map[string]any{
		"sub": "1234567890",
		"exp": 1, // 1970-01-01 + 1s — guaranteed past
	})
	findings := det.Detect(token, testCtx("env:STALE_TOKEN"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	// No specialized issuer → no token_subtype.
	_, hasSubtype := findings[0].Metadata["token_subtype"]
	assert.False(t, hasSubtype)
	assert.Equal(t, true, findings[0].Metadata["expired"])
	assert.Equal(t, int64(1), findings[0].Metadata["exp"])
}

func TestJWTDetector_MalformedPayloadFallsBackToGeneric(t *testing.T) {
	// Replace the payload with invalid base64url contents.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	// "!!!!" decodes cleanly under base64url but produces invalid JSON.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not-json-at-all`))
	token := header + "." + payload + ".signature_placeholder_long_enough"

	det := NewJWTDetector()
	findings := det.Detect(token, testCtx("file:malformed"))
	require.Len(t, findings, 1)
	assertStableJWS(t, findings[0])
	// Standard claims and subtype should NOT be set when decode fails.
	_, hasExpired := findings[0].Metadata["expired"]
	assert.False(t, hasExpired)
	_, hasSubtype := findings[0].Metadata["token_subtype"]
	assert.False(t, hasSubtype)
}
