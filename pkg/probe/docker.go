// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// DockerProbe extracts inline registry credentials from container
// runtime config files (Docker, Podman). The high-value secret is the
// `auths.<host>.auth` field: base64(user:password), stored unencrypted.
// When a credential helper is configured the field stays empty, which
// is the safer pattern — this probe surfaces the cases where it isn't.
//
// Posture findings (credsStore inventory, credHelpers mapping) are
// intentionally out of scope; they're not credentials.
type DockerProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewDockerProbe creates a container-config credential-extraction probe.
func NewDockerProbe(config models.ProbeSettings, registry *detector.Registry) *DockerProbe {
	return &DockerProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name.
func (p *DockerProbe) Name() string { return "docker" }

// IsEnabled returns whether the probe is enabled.
func (p *DockerProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *DockerProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *DockerProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute scans every indexed docker/podman config for inline auths.
func (p *DockerProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping docker probe")
		return nil, nil
	}

	var findings []models.Finding
	for _, src := range []struct {
		patternName string
		runtime     string
	}{
		{"docker_config", "docker"},
		{"podman_config", "podman"},
	} {
		for _, path := range p.fileIndex.Get(src.patternName) {
			findings = append(findings, p.processConfig(ctx, path, src.runtime)...)
		}
	}
	return findings, nil
}

// dockerConfigDoc is the minimum subset of docker config.json + podman
// auth.json we need. Other fields (HttpHeaders, proxies, plugins, etc.)
// don't carry stored credentials.
type dockerConfigDoc struct {
	Auths map[string]struct {
		Auth     string `json:"auth"`
		Username string `json:"username"`
		// IdentityToken is used by some registries (Azure ACR, ECR) in
		// lieu of basic auth; treat it as a credential too.
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
}

// processConfig parses one container config file and emits a finding
// per host that has an inline credential. The runtime arg ("docker" /
// "podman") goes into metadata so users can tell which CLI owns the
// file when the two configs are both present.
func (p *DockerProbe) processConfig(ctx context.Context, path, runtimeName string) []models.Finding {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", path).
			Msg("Cannot read docker config")
		return nil
	}

	var doc dockerConfigDoc
	if err := json.Unmarshal(content, &doc); err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", path).
			Msg("Cannot parse docker config JSON")
		return nil
	}

	var findings []models.Finding
	for host, entry := range doc.Auths {
		if entry.Auth != "" {
			findings = append(findings, p.findingFromAuth(ctx, path, runtimeName, host, entry.Auth)...)
		}
		if entry.IdentityToken != "" {
			findings = append(findings, p.findingFromIdentityToken(path, runtimeName, host, entry.IdentityToken)...)
		}
	}
	return findings
}

// findingFromAuth emits the inline-basic-auth finding plus any
// downstream classification the registry adds. The decoded password
// flows through the registry so a GitHub PAT, npm token, or JWT stored
// as the registry password gets surfaced with its specific type.
func (p *DockerProbe) findingFromAuth(
	ctx context.Context,
	path string,
	runtimeName string,
	host string,
	encoded string,
) []models.Finding {
	username, password, ok := decodeBasicAuth(encoded)
	if !ok {
		log.Ctx(ctx).Debug().
			Str("file", path).
			Str("host", host).
			Msg("Skipping malformed docker auth entry")
		return nil
	}

	// Bracket-and-quote notation keeps it
	// unambiguous when the registry host contains dots or slashes
	// (https://index.docker.io/v1/ being the canonical example).
	source := "file:" + path
	location := fmt.Sprintf("auths[%q].auth", host)
	primary := models.Finding{
		ID:          "docker-registry-inline-auth",
		Type:        models.FindingTypeSecret,
		Fingerprint: models.FingerprintFromFields("docker-registry-inline-auth", path, host),
		Probe:       p.Name(),
		Severity:    "critical",
		Title:       "Container Registry Credential Stored Inline",
		Description: "An inline base64(user:password) credential is stored in the container config. " +
			"Configure a credential helper (credsStore / credHelpers) so credentials live in the OS keychain " +
			"instead of on disk in cleartext.",
		Message: fmt.Sprintf("Inline registry credential for %s in file:%s", host, path),
		Path:    source,
		Metadata: map[string]interface{}{
			"runtime":          runtimeName,
			"registry_host":    host,
			"username":         username,
			"has_password":     password != "",
			"username_present": username != "",
			"location":         location,
		},
	}
	findings := make([]models.Finding, 0, 4)
	findings = append(findings, primary)

	// Run the decoded password through the registry. If it matches a
	// known token shape (GitHub PAT, JWT, npm token, etc.) those
	// findings get attached too — useful when users reuse a real PAT as
	// the registry password.
	if password != "" {
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    source,
			ProbeName: p.Name(),
		})
		for _, f := range p.detectorRegistry.DetectAll(password, detCtx) {
			if f.Metadata == nil {
				f.Metadata = make(map[string]interface{})
			}
			f.Metadata["runtime"] = runtimeName
			f.Metadata["registry_host"] = host
			f.Metadata["location"] = location
			findings = append(findings, f)
		}
	}
	return findings
}

// findingFromIdentityToken reports the ACR/ECR-style identitytoken
// field. We don't decode it (no fixed format), just surface its
// presence and feed it through the registry — JWT enrichment will
// classify it when applicable.
func (p *DockerProbe) findingFromIdentityToken(
	path string,
	runtimeName string,
	host string,
	token string,
) []models.Finding {
	source := "file:" + path
	location := fmt.Sprintf("auths[%q].identitytoken", host)
	primary := models.Finding{
		ID:          "docker-registry-inline-identity-token",
		Type:        models.FindingTypeSecret,
		Fingerprint: models.FingerprintFromFields("docker-registry-inline-identity-token", path, host),
		Probe:       p.Name(),
		Severity:    "critical",
		Title:       "Container Registry Identity Token Stored Inline",
		Description: "A registry identity token is stored in the container config. Identity tokens are " +
			"often long-lived OAuth refresh tokens; rotate the token and configure a credential helper.",
		Message: fmt.Sprintf("Inline registry identity token for %s in file:%s", host, path),
		Path:    source,
		Metadata: map[string]interface{}{
			"runtime":       runtimeName,
			"registry_host": host,
			"location":      location,
		},
	}
	findings := make([]models.Finding, 0, 4)
	findings = append(findings, primary)

	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    source,
		ProbeName: p.Name(),
	})
	for _, f := range p.detectorRegistry.DetectAll(token, detCtx) {
		if f.Metadata == nil {
			f.Metadata = make(map[string]interface{})
		}
		f.Metadata["runtime"] = runtimeName
		f.Metadata["registry_host"] = host
		f.Metadata["location"] = location
		findings = append(findings, f)
	}
	return findings
}

// decodeBasicAuth splits a base64(user:password) blob. Trailing
// newlines/whitespace can sneak in when humans hand-edit config.json,
// so trim before decoding. Both StdEncoding and RawStdEncoding are
// tried because some emitters omit padding.
func decodeBasicAuth(encoded string) (user, password string, ok bool) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", false
		}
	}
	user, password, ok = strings.Cut(string(raw), ":")
	if !ok {
		return "", "", false
	}
	return user, password, true
}
