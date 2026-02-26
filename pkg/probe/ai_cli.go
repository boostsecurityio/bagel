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

// AICliProbe checks ALI CLI credential and chat files
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

	// Process Gemini files
	for _, filePath := range geminiCreds {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}
	for _, filePath := range geminiChats {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	// Process Codex files
	for _, filePath := range codexCreds {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}
	for _, filePath := range codexChats {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	// Process Claude files
	for _, filePath := range claudeChats {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	// Process OpenCode files
	for _, filePath := range opencodeCreds {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}
	for _, filePath := range opencodeChats {
		fileFindings := p.processFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// processFile reads and analyzes an AI CLI adjacent file
func (p *AICliProbe) processFile(ctx context.Context, filePath string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

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
