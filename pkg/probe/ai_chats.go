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

// defaultAIChatsMaxFileSize caps reads of chat history files. The cap exists
// to keep regex scans bounded; sessions over this size are skipped.
const defaultAIChatsMaxFileSize = 1 * 1024 * 1024 // 1MB

// aiChatsPatterns lists the FileIndex pattern names whose matches hold AI
// CLI conversation history. These are append-only logs: scrubbing them is
// safe because tools don't read them back as state.
var aiChatsPatterns = []string{
	"gemini_chats",
	"codex_chats",
	"claude_chats",
	"opencode_chats",
}

// AIChatsProbe scans AI CLI conversation history files (jsonl, chat json).
// These are append-only session logs that often capture secrets the user
// pasted into prompts; both scan and scrub target them.
type AIChatsProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewAIChatsProbe creates a new AI CLI chat history probe.
// Accepts an optional flag "max_file_size" (int, in bytes) to override
// the default 1 MB per-file limit.
func NewAIChatsProbe(config models.ProbeSettings, registry *detector.Registry) *AIChatsProbe {
	return &AIChatsProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultAIChatsMaxFileSize),
	}
}

// Name returns the probe name.
func (p *AIChatsProbe) Name() string {
	return "ai_chats"
}

// IsEnabled returns whether the probe is enabled.
func (p *AIChatsProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *AIChatsProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *AIChatsProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the AI chats probe.
func (p *AIChatsProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping AI chats probe")
		return findings, nil
	}

	for _, pattern := range aiChatsPatterns {
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
