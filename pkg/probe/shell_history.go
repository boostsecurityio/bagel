// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// ShellHistoryProbe checks shell history files for secrets
type ShellHistoryProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewShellHistoryProbe creates a new shell history probe
func NewShellHistoryProbe(config models.ProbeSettings, registry *detector.Registry) *ShellHistoryProbe {
	return &ShellHistoryProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *ShellHistoryProbe) Name() string {
	return "shell_history"
}

// IsEnabled returns whether the probe is enabled
func (p *ShellHistoryProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *ShellHistoryProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *ShellHistoryProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the shell history probe
func (p *ShellHistoryProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping shell history probe")
		return findings, nil
	}

	// Get shell history files from file index
	historyFiles := p.fileIndex.Get("shell_history")

	log.Ctx(ctx).Debug().
		Int("history_files_count", len(historyFiles)).
		Msg("Found shell history files")

	// Process each history file
	for _, historyPath := range historyFiles {
		fileFindings := p.processHistoryFile(ctx, historyPath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// processHistoryFile reads and scans a shell history file for secrets
func (p *ShellHistoryProbe) processHistoryFile(ctx context.Context, historyPath string) []models.Finding {
	var findings []models.Finding

	// Open the file
	file, err := os.Open(historyPath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", historyPath).
			Msg("Cannot open shell history file")
		return findings
	}
	defer file.Close()

	// Read file line by line to handle large history files efficiently
	scanner := bufio.NewScanner(file)

	// Increase buffer size to handle very long command lines
	// Default is 64KB which may be too small for complex commands
	// Set to 1MB which should handle even the longest commands
	const maxLineSize = 1024 * 1024 // 1MB
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxLineSize)

	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse the history line to extract the actual command
		// This handles zsh extended history format (: timestamp:duration;command)
		command := parseHistoryLine(line)

		// Skip if command is empty after parsing
		if strings.TrimSpace(command) == "" {
			continue
		}

		// Scan the command for secrets using all detectors
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "file:" + historyPath,
			ProbeName: p.Name(),
		}).WithLineNumber(lineNum)

		detectedSecrets := p.detectorRegistry.DetectAll(command, detCtx)
		findings = append(findings, detectedSecrets...)
	}

	if err := scanner.Err(); err != nil {
		// Check for specific error types
		if errors.Is(err, bufio.ErrTooLong) {
			log.Ctx(ctx).Warn().
				Err(err).
				Str("file", historyPath).
				Int("max_line_size", maxLineSize).
				Msg("Command line exceeds maximum buffer size - this line will be skipped")
		} else {
			log.Ctx(ctx).Debug().
				Err(err).
				Str("file", historyPath).
				Msg("Error reading shell history file")
		}
	}

	return findings
}

// parseHistoryLine extracts the actual command from a shell history line.
// Handles:
//   - zsh extended history: `: timestamp:duration;command`
//   - fish history (YAML-like): `- cmd: command` and `  cmd: command`
//
// For bash and other plain-line formats it returns the line as-is. Fish's
// `when:` timestamp lines and other YAML metadata are returned as the empty
// string so callers can skip them.
func parseHistoryLine(line string) string {
	// zsh extended history: ": 1234567890:0;command"
	if strings.HasPrefix(line, ":") {
		semicolonIdx := strings.Index(line, ";")
		if semicolonIdx != -1 {
			return line[semicolonIdx+1:]
		}
	}

	// Fish history is a YAML stream of entries:
	//   - cmd: <command>
	//     when: <unix timestamp>
	//     paths:
	//       - <path>
	// Strip the YAML list marker and unescape the bare command. The metadata
	// rows ("when:", "paths:") aren't commands, so we drop them — leaving
	// them in would only feed YAML noise to the detectors.
	if cmd, ok := parseFishCmdLine(line); ok {
		return cmd
	}
	if isFishMetadataLine(line) {
		return ""
	}

	return line
}

// parseFishCmdLine returns the command portion of a fish history "cmd:" row
// and true if the line matched. Fish writes one entry per multiline YAML
// document, so the cmd line is either at the start of the entry ("- cmd: …")
// or as a continuation key ("  cmd: …").
func parseFishCmdLine(line string) (string, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	trimmed = strings.TrimPrefix(trimmed, "- ")
	const key = "cmd:"
	if !strings.HasPrefix(trimmed, key) {
		return "", false
	}
	cmd := strings.TrimLeft(trimmed[len(key):], " \t")
	return unescapeFishCmd(cmd), true
}

// isFishMetadataLine reports whether the line is a fish YAML metadata row
// that should be ignored ("when: ...", "paths:", "  - <path>").
func isFishMetadataLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" {
		return false
	}
	switch {
	case strings.HasPrefix(trimmed, "when:"):
		return true
	case strings.HasPrefix(trimmed, "paths:"):
		return true
	case strings.HasPrefix(trimmed, "- ") && !strings.HasPrefix(trimmed, "- cmd:"):
		// "  - /some/path" continuation under paths.
		return true
	}
	return false
}

// unescapeFishCmd reverses fish's YAML-style command escaping. Fish writes
// a backslash before any character it considers special when serializing
// history (newlines as "\n", backslashes as "\\", etc.). Leaving the escape
// sequences in place would split tokens like `ghp_…` mid-secret if they
// happened to contain a backslash-escaped char, so we materialize the
// original command before handing it to the detectors.
func unescapeFishCmd(cmd string) string {
	if !strings.ContainsRune(cmd, '\\') {
		return cmd
	}
	var b strings.Builder
	b.Grow(len(cmd))
	escaped := false
	for _, r := range cmd {
		if escaped {
			switch r {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteRune(r)
			}
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

// truncateCommand truncates a command to a reasonable length for display
func truncateCommand(cmd string) string {
	const maxLen = 100
	if len(cmd) <= maxLen {
		return cmd
	}
	return cmd[:maxLen] + "..."
}
