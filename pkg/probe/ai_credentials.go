// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// defaultAICredsMaxFileSize caps reads of credential files, which are
// always small. Anything larger is treated as accidental misclassification
// and skipped.
const defaultAICredsMaxFileSize = 1 * 1024 * 1024 // 1MB

// aiCredentialsPatterns lists the FileIndex pattern names whose matches
// hold AI CLI credentials. Tools require these files to authenticate, so
// scrub deliberately leaves them alone — only scan reports them.
var aiCredentialsPatterns = []string{
	"gemini_credentials",
	"codex_credentials",
	"opencode_credentials",
}

// AICredentialsProbe scans AI CLI credential files (auth.json, oauth_creds.json).
// These files are required by their respective tools for authentication, so they
// are scan-only — running scrub against them would log the user out.
type AICredentialsProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewAICredentialsProbe creates a new AI CLI credentials probe.
// Accepts an optional flag "max_file_size" (int, in bytes) to override
// the default 1 MB file size limit.
func NewAICredentialsProbe(config models.ProbeSettings, registry *detector.Registry) *AICredentialsProbe {
	return &AICredentialsProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultAICredsMaxFileSize),
	}
}

// Name returns the probe name.
func (p *AICredentialsProbe) Name() string {
	return "ai_credentials"
}

// IsEnabled returns whether the probe is enabled.
func (p *AICredentialsProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *AICredentialsProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *AICredentialsProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the AI credentials probe.
func (p *AICredentialsProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping AI credentials probe")
		return findings, nil
	}

	for _, pattern := range aiCredentialsPatterns {
		for _, filePath := range p.fileIndex.Get(pattern) {
			select {
			case <-ctx.Done():
				log.Ctx(ctx).Debug().
					Str("probe", p.Name()).
					Msg("Context cancelled, returning partial findings")
				return findings, nil
			default:
			}
			findings = append(findings, scanAIFile(ctx, filePath, p.Name(), p.detectorRegistry, p.maxFileSize)...)
		}
	}

	return findings, nil
}
