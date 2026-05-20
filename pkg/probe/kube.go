// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unicode"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// defaultKubeMaxFileSize caps the per-file read on kubeconfig parsing.
// Real kubeconfigs are tens of KB at most; anything larger is almost
// certainly accidental and risks unbounded YAML decode.
const defaultKubeMaxFileSize = 1 * 1024 * 1024 // 1 MB

// KubeProbe extracts credentials embedded in kubeconfig files: bearer
// tokens (caught by the registry — JWT enrichment classifies K8s SA
// JWTs), inline client-key-data PEM blocks (base64-encoded in the YAML,
// caught by the SSH private key detector once decoded), and any other
// plaintext secret the registry recognizes.
//
// Posture findings (auth method classification, file permissions,
// current context) are intentionally out of scope — the probe's job
// here is credential discovery, not configuration audit.
type KubeProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewKubeProbe creates a kubeconfig credential-extraction probe.
// Accepts an optional flag "max_file_size" (int, bytes) overriding the
// default 1 MB read cap.
func NewKubeProbe(config models.ProbeSettings, registry *detector.Registry) *KubeProbe {
	return &KubeProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultKubeMaxFileSize),
	}
}

// Name returns the probe name.
func (p *KubeProbe) Name() string { return "kube" }

// IsEnabled returns whether the probe is enabled.
func (p *KubeProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *KubeProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *KubeProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the kubeconfig credential extraction.
func (p *KubeProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	paths := p.collectKubeconfigPaths(ctx)
	if len(paths) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{}, len(paths))
	var findings []models.Finding
	for _, path := range paths {
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		findings = append(findings, p.processKubeconfig(ctx, path)...)
	}
	return findings, nil
}

// collectKubeconfigPaths gathers candidate kubeconfig file paths from
// both the file index (~/.kube/config matches) and the KUBECONFIG env
// var, which often points at non-home paths (e.g. /etc/rancher/k3s/k3s.yaml).
func (p *KubeProbe) collectKubeconfigPaths(ctx context.Context) []string {
	var paths []string

	if p.fileIndex != nil {
		paths = append(paths, p.fileIndex.Get("kubeconfig")...)
	} else {
		log.Ctx(ctx).Debug().
			Str("probe", p.Name()).
			Msg("File index not available; relying on KUBECONFIG env only")
	}

	if env := os.Getenv("KUBECONFIG"); env != "" {
		sep := ":"
		if runtime.GOOS == "windows" {
			sep = ";"
		}
		for _, p := range strings.Split(env, sep) {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			paths = append(paths, p)
		}
	}
	return paths
}

// processKubeconfig walks one kubeconfig file. The line-scan picks up
// plaintext tokens and bearer credentials (registered detectors classify
// each), and the YAML walk base64-decodes inline client keys so the
// existing PEM detector catches them.
func (p *KubeProbe) processKubeconfig(ctx context.Context, path string) []models.Finding {
	info, err := os.Stat(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot stat kubeconfig")
		return nil
	}
	if info.Size() > p.maxFileSize {
		log.Ctx(ctx).Debug().
			Str("file", path).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", p.maxFileSize).
			Msg("Skipping oversized kubeconfig")
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot read kubeconfig")
		return nil
	}

	// Scan the bytes we already read instead of re-opening the file —
	// one I/O round-trip plus zero TOCTOU window between line scan and
	// YAML parse (they operate on the same content). Matches the
	// pattern in pkg/probe/npm.go.
	findings := scanReaderLines(ctx, "file:"+path, bytes.NewReader(content), p.Name(), p.detectorRegistry, int(p.maxFileSize)+1)

	// YAML walk extracts base64-wrapped credentials that the line scan
	// can't see — the user's inline client key is the high-value one.
	findings = append(findings, p.extractEncodedCredentials(ctx, path, content)...)

	return findings
}

// kubeconfigDoc is the minimal subset of the kubeconfig schema we need
// to reach the credential-bearing fields. We deliberately ignore
// clusters/contexts/preferences — none of those carry secrets.
type kubeconfigDoc struct {
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			// Base64-encoded PEM private key — the actual secret in
			// cert-based auth. The matching client-certificate-data is
			// the *public* cert; we ignore it.
			ClientKeyData string `yaml:"client-key-data"`
			// Some kubeconfigs (older tools) inline the token directly
			// in `token-data` (base64) instead of `token`. Treat both.
			TokenData string `yaml:"token-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// extractEncodedCredentials decodes the base64-wrapped credential
// fields in a kubeconfig and runs the detector registry over each
// decoded blob. Each decoded blob carries a synthetic source like
// "file:<path>#users[<idx>].user.client-key-data" so the finding's
// location still points back to something a user can find.
func (p *KubeProbe) extractEncodedCredentials(ctx context.Context, path string, content []byte) []models.Finding {
	var doc kubeconfigDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", path).
			Msg("Cannot parse kubeconfig YAML")
		return nil
	}

	var findings []models.Finding
	for i, u := range doc.Users {
		findings = append(findings,
			p.scanEncoded(ctx, path, i, u.Name, "client-key-data", u.User.ClientKeyData)...)
		findings = append(findings,
			p.scanEncoded(ctx, path, i, u.Name, "token-data", u.User.TokenData)...)
	}
	return findings
}

// scanEncoded base64-decodes one kubeconfig credential field and feeds
// the result to the registry. The synthetic Source string is what
// findings get tagged with — pointing back to the kubeconfig path plus
// the YAML location is enough for a user to find the secret.
func (p *KubeProbe) scanEncoded(
	ctx context.Context,
	path string,
	userIdx int,
	userName string,
	field string,
	encoded string,
) []models.Finding {
	if encoded == "" {
		return nil
	}
	decoded, err := decodeBase64Loose(encoded)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", path).
			Int("user_index", userIdx).
			Str("field", field).
			Msg("Cannot base64-decode kubeconfig field")
		return nil
	}

	source := "file:" + path
	location := fmt.Sprintf("users[%d].user.%s", userIdx, field)
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    source,
		ProbeName: p.Name(),
	})
	found := p.detectorRegistry.DetectAll(string(decoded), detCtx)

	// Annotate so the user knows which kubeconfig user the credential
	// belongs to — that's the bit they need to revoke.
	for i := range found {
		if found[i].Metadata == nil {
			found[i].Metadata = make(map[string]interface{})
		}
		found[i].Metadata["kubeconfig_path"] = path
		found[i].Metadata["kubeconfig_user"] = userName
		found[i].Metadata["kubeconfig_field"] = field
		found[i].Metadata["location"] = location
	}
	return found
}

// decodeBase64Loose strips all whitespace from s and decodes it as
// base64. YAML block scalars (`|` / `>`) and many hand-written
// kubeconfigs wrap long base64 values across multiple lines, so
// TrimSpace alone misses embedded newlines/tabs. Falls back to
// RawStdEncoding because some emitters omit padding.
func decodeBase64Loose(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("base64 decode kubeconfig field: %w", err)
	}
	return b, nil
}
