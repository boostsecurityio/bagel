// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// JWTDetector detects JWT tokens in various contexts
type JWTDetector struct {
	tokenPatterns  map[string]*tokenPattern
	redactPatterns []RedactPattern
}

// NewJWTDetector creates a new JWT detector
func NewJWTDetector() *JWTDetector {
	return &JWTDetector{
		// Standalone JWT redaction (after Bearer patterns handled by HTTPAuthDetector)
		redactPatterns: []RedactPattern{
			{
				Regex: regexp.MustCompile(
					`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
				Replacement: `[REDACTED-jwt]`,
				Label:       "REDACTED-jwt",
				Prefixes:    []string{"eyJ"},
			},
		},
		tokenPatterns: map[string]*tokenPattern{
			"jwt-token": {
				// Matches: <base64_header>.<base64_payload>.<base64_sig>
				// The header is constrained with ey since any valid header should be a JSON object with at least one member (alg)
				// The same can't be said for the body (ex: {}), the signature also has no fixed format (binary data)
				regex:       regexp.MustCompile(`\b(ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)\b($|[^.])`),
				tokenType:   "jwt-token",
				description: "JWT Token",
				title:       "JWT Token Detected",
			},
			"jwe-token": {
				// Matches: <base64_header>.<base64_enc_key>.<base64_iv>.<base64_ct>.<base64_tag>
				// The header is constrained with ey since any valid header should be a JSON object with at least one member (alg)
				// The same can't be said for any of the other sections
				regex:       regexp.MustCompile(`\b(ey[A-Za-z0-9-_]+(?:\.[A-Za-z0-9-_]+){4})\b`),
				tokenType:   "jwe-token",
				description: "JWE Token",
				title:       "JWE Token Detected",
			},
		},
	}
}

// Name returns the detector name
func (d *JWTDetector) Name() string {
	return "jwt"
}

// Detect scans content for JWT tokens and returns findings
func (d *JWTDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	// Check for all token formats
	for _, pattern := range d.tokenPatterns {
		matches := pattern.regex.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				// Extract the token from the capture group
				credential := match[1]
				findings = append(findings, d.createFinding(credential, pattern, ctx))
			}
		}
	}

	return findings
}

// Redact replaces standalone JWT tokens in content with redaction markers.
func (d *JWTDetector) Redact(content string) (string, map[string]int) {
	return ApplyRedactPatterns(content, d.redactPatterns)
}

// createFinding creates a finding for a detected JWT. The finding's ID,
// Title, and base token_type metadata are kept stable across releases —
// users filter and dedupe on those. Issuer-specific enrichment (K8s SA,
// GitHub OIDC, AWS IRSA, etc.) is surfaced purely in metadata via
// token_subtype + classifier-specific fields. JWEs carry encrypted
// payloads, so they only ever get the generic classification.
func (d *JWTDetector) createFinding(credential string, pattern *tokenPattern, ctx *models.DetectionContext) models.Finding {
	metadata := map[string]any{
		"detector_name": d.Name(),
		"description":   pattern.description,
		"token_type":    pattern.tokenType,
	}

	if claims := parseJWTClaims(credential); claims != nil {
		if cls := classifyJWT(claims); cls.subtype != "" {
			metadata["token_subtype"] = cls.subtype
			for k, v := range cls.extras {
				metadata[k] = v
			}
		}
		populateStandardClaims(metadata, claims)
	}

	return models.Finding{
		ID:          "jwt-" + pattern.tokenType,
		Type:        models.FindingTypeSecret,
		Fingerprint: models.SaltedFingerprint(credential, ctx.FingerprintSalt),
		Severity:    "critical",
		Title:       pattern.title,
		Description: "JWT tokens in plain text can be exposed in logs, shell history, or configuration files. " +
			"Use secure credential storage or secret management systems instead.",
		Message:  fmt.Sprintf("A %s was detected in %s.", pattern.description, ctx.FormatSource()),
		Path:     ctx.Source,
		Metadata: metadata,
	}
}

// jwtClaims is the subset of registered + well-known claims we surface.
// All fields are optional; an unrecognized payload decodes into an empty
// struct and falls back to the generic jwt-token classification.
type jwtClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"` // string or []string per RFC 7519
	Exp json.Number     `json:"exp"`
	Iat json.Number     `json:"iat"`

	// Kubernetes bound/projected SA tokens carry namespace + SA name
	// under this nested claim. Presence is the strongest K8s signal,
	// since the iss varies across legacy / bound / projected formats.
	KubernetesIO *struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io,omitempty"`

	// GitHub Actions OIDC claims (iss == token.actions.githubusercontent.com)
	Repository string `json:"repository"`
	Workflow   string `json:"workflow"`
	Ref        string `json:"ref"`
	Actor      string `json:"actor"`

	// Azure AD claims (iss == sts.windows.net/<tid>/ or login.microsoftonline.com/<tid>/v2.0)
	Tid   string `json:"tid"`
	Appid string `json:"appid"`
}

// jwtClassification holds the issuer-specific enrichment for a JWT
// finding. subtype == "" means no classifier matched; the caller emits
// no token_subtype metadata. The base ID/Title/token_type on the finding
// always stay generic (jwt-token / jwe-token) so callers that filter on
// those don't see existing findings change shape across releases.
type jwtClassification struct {
	subtype string
	extras  map[string]any
}

var awsIRSAIssuerRegex = regexp.MustCompile(`^https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/`)

// classifyJWT walks claims in priority order. K8s SA wins over Vault aud
// because a Vault-audienced K8s SA token is operationally a K8s SA
// token; the SA classification carries more useful metadata.
func classifyJWT(c *jwtClaims) jwtClassification {
	if c == nil {
		return jwtClassification{}
	}

	if c.KubernetesIO != nil ||
		strings.HasPrefix(c.Sub, "system:serviceaccount:") ||
		c.Iss == "kubernetes/serviceaccount" {
		extras := map[string]any{}
		if c.KubernetesIO != nil {
			if ns := c.KubernetesIO.Namespace; ns != "" {
				extras["k8s_namespace"] = ns
			}
			if name := c.KubernetesIO.ServiceAccount.Name; name != "" {
				extras["k8s_serviceaccount"] = name
			}
		}
		return jwtClassification{
			subtype: "jwt-kubernetes-service-account",
			extras:  extras,
		}
	}

	if c.Iss == "https://token.actions.githubusercontent.com" {
		extras := map[string]any{}
		if c.Repository != "" {
			extras["github_repository"] = c.Repository
		}
		if c.Workflow != "" {
			extras["github_workflow"] = c.Workflow
		}
		if c.Ref != "" {
			extras["github_ref"] = c.Ref
		}
		if c.Actor != "" {
			extras["github_actor"] = c.Actor
		}
		return jwtClassification{
			subtype: "jwt-github-actions-oidc",
			extras:  extras,
		}
	}

	if awsIRSAIssuerRegex.MatchString(c.Iss) {
		return jwtClassification{
			subtype: "jwt-aws-irsa",
			extras:  map[string]any{"oidc_issuer": c.Iss},
		}
	}

	if strings.HasPrefix(c.Iss, "https://sts.windows.net/") ||
		strings.HasPrefix(c.Iss, "https://login.microsoftonline.com/") {
		extras := map[string]any{}
		if c.Tid != "" {
			extras["azure_tenant"] = c.Tid
		}
		if c.Appid != "" {
			extras["azure_app_id"] = c.Appid
		}
		return jwtClassification{
			subtype: "jwt-azure-ad",
			extras:  extras,
		}
	}

	if c.Iss == "https://accounts.google.com" || c.Iss == "accounts.google.com" {
		return jwtClassification{
			subtype: "jwt-gcp-id-token",
		}
	}
	if strings.HasSuffix(c.Iss, ".iam.gserviceaccount.com") {
		return jwtClassification{
			subtype: "jwt-gcp-service-account",
			extras:  map[string]any{"gcp_service_account": c.Iss},
		}
	}

	if audContainsVault(c.Aud) {
		return jwtClassification{
			subtype: "jwt-vault-auth",
		}
	}

	return jwtClassification{}
}

// audContainsVault returns true when the aud claim names a Vault
// endpoint. RFC 7519 allows aud to be a single string or array of
// strings; handle both. Substring "vault" is a conservative match —
// users typically configure aud values like "vault" or
// "vault.example.com".
func audContainsVault(raw json.RawMessage) bool {
	for _, a := range normalizeAud(raw) {
		if strings.Contains(strings.ToLower(a), "vault") {
			return true
		}
	}
	return false
}

// normalizeAud returns aud as a string slice regardless of whether the
// JWT encoded it as a string or an array.
func normalizeAud(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	return nil
}

// populateStandardClaims fills the registered-claim subset every
// successful decode should surface. Specialized classifiers add their
// own fields on top.
func populateStandardClaims(metadata map[string]any, c *jwtClaims) {
	if c.Iss != "" {
		metadata["iss"] = c.Iss
	}
	if c.Sub != "" {
		metadata["sub"] = c.Sub
	}
	if aud := normalizeAud(c.Aud); len(aud) > 0 {
		metadata["aud"] = aud
	}
	if exp, ok := numericClaim(c.Exp); ok {
		metadata["exp"] = exp
		metadata["expired"] = time.Now().Unix() >= exp
	}
	if iat, ok := numericClaim(c.Iat); ok {
		metadata["iat"] = iat
	}
}

// parseJWTClaims best-effort decodes the payload of a JWS (3 segments).
// Returns nil for JWEs (5 segments) or any decode error — callers fall
// back to generic classification. Signatures are never verified;
// classification is metadata-only and the token is already at rest on
// the user's filesystem.
func parseJWTClaims(token string) *jwtClaims {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var c jwtClaims
	if err := decoder.Decode(&c); err != nil {
		return nil
	}
	return &c
}

// decodeJWTSegment base64url-decodes a single JWT segment. RFC 7515
// mandates unpadded base64url, but some emitters add padding — try both
// before giving up.
func decodeJWTSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	b, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("base64url decode jwt segment: %w", err)
	}
	return b, nil
}

// numericClaim converts a json.Number-typed claim (exp, iat) to int64,
// tolerating implementations that emit the value as a JSON float.
func numericClaim(n json.Number) (int64, bool) {
	if n == "" {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return v, true
	}
	if f, err := n.Float64(); err == nil {
		return int64(f), true
	}
	return 0, false
}
