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

// maxChatFileSize is the maximum size of an AI chat log file that will be scanned.
// Files larger than this limit are skipped to prevent unbounded memory usage and
// scan hangs when users accumulate large conversation histories.
const maxChatFileSize = 1 * 1024 * 1024 // 1MB

// AICliProbe checks AI CLI credential and chat files
type AICliProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewAICliProbe creates a new AI CLI credentials probe
func NewAICliProbe(config models.ProbeSettings, registry *detector.Registry) *AICliProbe {
	return &AICliProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *AICliProbe) Name() string {
	return "ai_cli"
}

// IsEnabled returns whether the probe is enabled
func (p *AICliProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *AICliProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *AICliProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the AI cli probe
func (p *AICliProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping AI cli probe")
		return findings, nil
	}

	// Get auth files and chat files from file index
	geminiCreds := p.fileIndex.Get("gemini_credentials")
	codexCreds := p.fileIndex.Get("codex_credentials")
	opencodeCreds := p.fileIndex.Get("opencode_credentials")

	geminiChats := p.fileIndex.Get("gemini_chats")
	codexChats := p.fileIndex.Get("codex_chats")
	claudeChats := p.fileIndex.Get("claude_chats")
	opencodeChats := p.fileIndex.Get("opencode_chats")

	log.Ctx(ctx).Debug().
		Int("gemini_credentials_count", len(geminiCreds)).
		Int("codex_credentials_countr", len(codexCreds)).
		Int("opencode_credentials_count", len(opencodeCreds)).
		Msg("Found AI CLI credential files")

	log.Ctx(ctx).Debug().
		Int("gemini_chats_count", len(geminiChats)).
		Int("codex_chats_count", len(codexChats)).
		Int("claude_chats_count", len(claudeChats)).
		Int("opencode_chats_count", len(opencodeChats)).
		Msg("Found AI CLI chat log files")

	fileSets := [][]string{
		geminiCreds,
		geminiChats,
		codexCreds,
		codexChats,
		claudeChats,
		opencodeCreds,
		opencodeChats,
	}

	for _, files := range fileSets {
		for _, filePath := range files {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}
			fileFindings := p.processFile(ctx, filePath)
			findings = append(findings, fileFindings...)
		}
	}

	return findings, nil
}

// processFile reads and analyzes an AI CLI adjacent file
func (p *AICliProbe) processFile(ctx context.Context, filePath string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

	// Check file size before reading to avoid loading large chat logs into memory.
	// Credential files are small; oversized files are almost certainly conversation
	// history where a full regex scan would be unbounded and slow.
	info, err := os.Stat(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot stat AI CLI file")
		return findings
	}
	if info.Size() > maxChatFileSize {
		log.Ctx(ctx).Debug().
			Str("file", filePath).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", maxChatFileSize).
			Msg("Skipping oversized AI CLI chat file")
		return findings
	}

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read AI CLI file")
		return findings
	}

	contentStr := string(content)

	// Use detector registry to scan for AI CLI credentials
	// and leaked secrets / credentials in chat logs
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	detectedCreds := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedCreds...)

	return findings
}
