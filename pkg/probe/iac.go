// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// defaultIaCMaxFileSize caps each per-file read. tfvars and tfstate
// files can grow large in real projects but anything past this is
// almost certainly accidental (e.g. checked-in plan output); keeping
// the bound prevents unbounded YAML/JSON decode.
const defaultIaCMaxFileSize = 4 * 1024 * 1024 // 4 MB

// IaCProbe extracts credentials embedded in Infrastructure-as-Code
// files: Terraform Cloud API tokens (credentials.tfrc.json /
// .terraformrc), cloud creds and DB passwords baked into *.tfvars,
// resource outputs serialized in local terraform.tfstate, and
// username/password fields in Helm's repositories.yaml.
//
// Posture findings (file permissions, config completeness) are out of
// scope — the probe targets credentials specifically.
type IaCProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewIaCProbe creates an IaC credential-extraction probe.
// Accepts an optional flag "max_file_size" (int, bytes) overriding the
// default 4 MB read cap.
func NewIaCProbe(config models.ProbeSettings, registry *detector.Registry) *IaCProbe {
	return &IaCProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultIaCMaxFileSize),
	}
}

// Name returns the probe name.
func (p *IaCProbe) Name() string { return "iac" }

// IsEnabled returns whether the probe is enabled.
func (p *IaCProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *IaCProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *IaCProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute walks every IaC file pattern and dispatches per shape.
func (p *IaCProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping IaC probe")
		return nil, nil
	}

	var findings []models.Finding

	for _, path := range p.fileIndex.Get("terraform_credentials") {
		findings = append(findings, p.processTerraformCredentials(ctx, path)...)
	}
	// tfvars / tfstate / helm files all benefit from the same
	// line-scan-then-fall-through-to-registry approach. Existing
	// detectors (cloud creds, JWT, generic API key, DB connection
	// strings, slack/stripe/twilio) cover the secret shapes.
	for _, path := range p.fileIndex.Get("terraform_vars") {
		findings = append(findings, p.scanThroughRegistry(ctx, path)...)
	}
	for _, path := range p.fileIndex.Get("terraform_state") {
		findings = append(findings, p.scanThroughRegistry(ctx, path)...)
	}
	for _, path := range p.fileIndex.Get("helm_repositories") {
		findings = append(findings, p.processHelmRepositories(ctx, path)...)
	}

	return findings, nil
}

// readBounded reads a file but caps it at maxFileSize. Returns nil if
// the file is missing or oversized; logs at debug in both cases.
func (p *IaCProbe) readBounded(ctx context.Context, path string) []byte {
	info, err := os.Stat(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot stat IaC file")
		return nil
	}
	if info.Size() > p.maxFileSize {
		log.Ctx(ctx).Debug().
			Str("file", path).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", p.maxFileSize).
			Msg("Skipping oversized IaC file")
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot read IaC file")
		return nil
	}
	return content
}

// scanThroughRegistry feeds every line of a file to the detector
// registry. Used for free-form IaC content (tfvars, tfstate) where
// secrets show up as embedded strings caught by the existing
// detectors.
func (p *IaCProbe) scanThroughRegistry(ctx context.Context, path string) []models.Finding {
	content := p.readBounded(ctx, path)
	if content == nil {
		return nil
	}
	return scanReaderLines(ctx, "file:"+path, bytes.NewReader(content), p.Name(), p.detectorRegistry, int(p.maxFileSize)+1)
}

// terraformCredentialsJSON is the schema of credentials.tfrc.json.
// `terraform login` writes this; the legacy .terraformrc HCL form is
// handled with a regex below.
type terraformCredentialsJSON struct {
	Credentials map[string]struct {
		Token string `json:"token"`
	} `json:"credentials"`
}

// terraformrcCredsRegex matches the HCL form:
//
//	credentials "app.terraform.io" {
//	  token = "atlas.v1.…"
//	}
//
// It tolerates flexible whitespace and either single or double quotes
// around the token, which terraform CLI itself accepts.
var terraformrcCredsRegex = regexp.MustCompile(
	`credentials\s+["']([^"']+)["']\s*\{[^}]*?token\s*=\s*["']([^"']+)["']`,
)

// processTerraformCredentials emits a finding per Terraform Cloud /
// Enterprise host with a stored API token. JSON is preferred; HCL is a
// best-effort fallback.
func (p *IaCProbe) processTerraformCredentials(ctx context.Context, path string) []models.Finding {
	content := p.readBounded(ctx, path)
	if content == nil {
		return nil
	}

	// JSON form first — it's authoritative.
	var doc terraformCredentialsJSON
	if err := json.Unmarshal(content, &doc); err == nil && len(doc.Credentials) > 0 {
		findings := make([]models.Finding, 0, len(doc.Credentials))
		for host, entry := range doc.Credentials {
			if entry.Token == "" {
				continue
			}
			findings = append(findings, p.terraformCredentialFinding(path, host, entry.Token, "json"))
		}
		return findings
	}

	// HCL fallback — terraform CLI itself accepts both formats.
	matches := terraformrcCredsRegex.FindAllStringSubmatch(string(content), -1)
	findings := make([]models.Finding, 0, len(matches))
	for _, m := range matches {
		host, token := m[1], m[2]
		if token == "" {
			continue
		}
		findings = append(findings, p.terraformCredentialFinding(path, host, token, "hcl"))
	}
	return findings
}

func (p *IaCProbe) terraformCredentialFinding(path, host, token, format string) models.Finding {
	return models.Finding{
		ID:          "terraform-cloud-credential",
		Type:        models.FindingTypeSecret,
		Fingerprint: models.FingerprintFromFields("terraform-cloud-credential", path, host),
		Probe:       p.Name(),
		Severity:    "critical",
		Title:       "Terraform Cloud/Enterprise API Token Stored Locally",
		Description: "A Terraform Cloud or Enterprise API token is stored in plaintext. " +
			"These tokens grant full API access to workspaces, state, and runs. Revoke " +
			"and re-create the token from the Terraform Cloud UI if the host is shared.",
		Message: fmt.Sprintf("Terraform credential for %s in file:%s", host, path),
		// Path stays a plain `file:<absolute path>` so terminals'
		// open-file affordances work; the in-file location goes to
		// metadata where structured consumers can read it.
		Path: "file:" + path,
		Metadata: map[string]interface{}{
			"host":           host,
			"file_format":    format,
			"token_prefix":   tokenPrefix(token),
			"token_fragment": maskFragment(token),
			"location":       fmt.Sprintf("credentials[%q].token", host),
		},
	}
}

// helmRepositoriesDoc is the minimum subset of repositories.yaml needed
// to reach username/password fields. Helm has many other fields that
// aren't credentials.
type helmRepositoriesDoc struct {
	Repositories []struct {
		Name     string `yaml:"name"`
		URL      string `yaml:"url"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"repositories"`
}

// processHelmRepositories emits a finding per Helm repo entry that has
// a non-empty password. Plain `name + url` entries (the public-chart
// case) are silently skipped.
func (p *IaCProbe) processHelmRepositories(ctx context.Context, path string) []models.Finding {
	content := p.readBounded(ctx, path)
	if content == nil {
		return nil
	}
	var doc helmRepositoriesDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot parse Helm repositories.yaml")
		return nil
	}
	findings := make([]models.Finding, 0, len(doc.Repositories))
	for _, r := range doc.Repositories {
		if r.Password == "" {
			continue
		}
		findings = append(findings, models.Finding{
			ID:          "helm-repository-credential",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.FingerprintFromFields("helm-repository-credential", path, r.Name),
			Probe:       p.Name(),
			Severity:    "critical",
			Title:       "Helm Repository Credential Stored Inline",
			Description: "A Helm repository entry stores a password in plaintext. " +
				"Configure a credentials helper or pass --username/--password at install time " +
				"so the secret doesn't sit on disk.",
			Message: fmt.Sprintf("Helm credential for repo %q (%s) in file:%s", r.Name, r.URL, path),
			Path:    "file:" + path,
			Metadata: map[string]interface{}{
				"repo_name":        r.Name,
				"repo_url":         r.URL,
				"username":         r.Username,
				"username_present": r.Username != "",
				"location":         fmt.Sprintf("repositories[%s]", r.Name),
			},
		})
	}
	return findings
}

// tokenPrefix returns the first <= 8 characters of a token. Useful for
// recognizing the token family (atlas.v1, hvs., etc.) without leaking
// the secret value.
func tokenPrefix(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8]
}

// maskFragment returns a short masked indicator of a token's length —
// e.g. "atlas.v1.…(64)" — so users can confirm which token is meant
// without surfacing the full value.
func maskFragment(token string) string {
	return fmt.Sprintf("%s…(%d)", tokenPrefix(token), len(token))
}
