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

// defaultAIContextMaxFileSize caps memory/context Markdown reads.
// Project CLAUDE.md / AGENTS.md files are normally a few KB; anything
// past 1 MB is most likely accidental and skipping is preferable to
// unbounded scan.
const defaultAIContextMaxFileSize = 1 * 1024 * 1024

// ContextProbe scans AI agent context/memory files for credentials
// users have pasted into them. CLAUDE.md (Claude Code) and AGENTS.md
// (Codex / OpenCode / cross-tool convention) are both user-authored
// Markdown that the agent loads as system context — secrets baked
// into them get sent to the model on every invocation and stick
// around in the repo history.
//
// Scan-only: scrub never touches these. They're user-authored docs;
// silently rewriting them would surprise users and risk breaking
// formatting that matters to the agent.
type ContextProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewContextProbe creates the AI context/memory probe.
func NewContextProbe(config models.ProbeSettings, registry *detector.Registry) *ContextProbe {
	return &ContextProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultAIContextMaxFileSize),
	}
}

// Name returns the probe name.
func (p *ContextProbe) Name() string { return "ai_context" }

// IsEnabled returns whether the probe is enabled.
func (p *ContextProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *ContextProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *ContextProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// aiContextPatterns lists every file-index pattern whose matches hold
// AI agent user-authored context. Memory files (CLAUDE.md / AGENTS.md)
// are basename-globbed so they catch every project; command/agent/
// skill/instruction patterns are user-level (~/.claude, ~/.codex,
// ~/.agents) because the file index doesn't support `**` globs and
// project-level versions would need that.
var aiContextPatterns = []string{
	"ai_memory_md",       // CLAUDE.md / AGENTS.md anywhere under home
	"claude_commands",    // ~/.claude/commands/*.md
	"claude_agents",      // ~/.claude/agents/*.md
	"claude_skills",      // ~/.claude/skills/*/*.md
	"agents_skills",      // ~/.agents/skills/*/*.md (cross-agent convention)
	"codex_instructions", // ~/.codex/instructions.md
	"codex_memories",     // ~/.codex/memories/*
	"codex_skills",       // ~/.codex/skills/*/*.md
}

// Execute walks every indexed context/memory file and line-scans them
// through the detector registry.
func (p *ContextProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping ai_context probe")
		return nil, nil
	}

	seen := make(map[string]struct{})
	var findings []models.Finding
	for _, pattern := range aiContextPatterns {
		for _, path := range p.fileIndex.Get(pattern) {
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			findings = append(findings, p.scanFile(ctx, path)...)
		}
	}
	return findings, nil
}

// scanFile reads one Markdown file (bounded) and runs the detector
// registry line-by-line. Per-line scanning gives every finding a line
// number so users can jump straight to the secret.
func (p *ContextProbe) scanFile(ctx context.Context, path string) []models.Finding {
	info, err := os.Stat(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot stat AI context file")
		return nil
	}
	if info.Size() > p.maxFileSize {
		log.Ctx(ctx).Debug().
			Str("file", path).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", p.maxFileSize).
			Msg("Skipping oversized AI context file")
		return nil
	}
	return scanFileLines(ctx, path, p.Name(), p.detectorRegistry, int(p.maxFileSize)+1)
}
