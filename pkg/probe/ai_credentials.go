// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"

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

// readMaxFileSizeFlag pulls "max_file_size" out of probe flags, falling back
// to the supplied default. Shared by AICredentialsProbe and AIChatsProbe.
func readMaxFileSizeFlag(flags map[string]interface{}, fallback int64) int64 {
	v, ok := flags["max_file_size"]
	if !ok {
		return fallback
	}
	switch val := v.(type) {
	case int:
		return int64(val)
	case int64:
		return val
	case float64:
		return int64(val)
	}
	return fallback
}

// scanAIFile reads and analyzes an AI CLI adjacent file. JSONL chat logs are
// line-per-message and credential JSON files keep secret values (e.g.
// service-account private_key) on a single line via \n escape sequences, so
// per-line scanning is sufficient and gives us line numbers.
func scanAIFile(
	ctx context.Context,
	filePath string,
	probeName string,
	registry *detector.Registry,
	maxFileSize int64,
) []models.Finding {
	// Check file size before reading to avoid loading large files into memory.
	// Credential files are small; oversized files are almost certainly
	// conversation history where a full regex scan would be unbounded and slow.
	info, err := os.Stat(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot stat AI CLI file")
		return nil
	}
	if info.Size() > maxFileSize {
		log.Ctx(ctx).Debug().
			Str("file", filePath).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", maxFileSize).
			Msg("Skipping oversized AI CLI file")
		return nil
	}

	// JSONL chat lines (model responses, large prompts) can exceed bufio's
	// default 64KB. Cap at maxFileSize since the whole file already fits.
	return scanFileLines(ctx, filePath, probeName, registry, int(maxFileSize)+1)
}
