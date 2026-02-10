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

// parseHistoryLine extracts the actual command from a shell history line
// Handles zsh extended history format: `: timestamp:duration;command`
// For other shells (bash, etc.), returns the line as-is
func parseHistoryLine(line string) string {
	// Check if this is a zsh extended history entry
	// Format: : 1234567890:0;command
	if strings.HasPrefix(line, ":") {
		// Find the semicolon that separates metadata from command
		semicolonIdx := strings.Index(line, ";")
		if semicolonIdx != -1 {
			// Return everything after the semicolon (may be empty)
			return line[semicolonIdx+1:]
		}
	}

	// For bash or other formats, return the line as-is
	return line
}

// truncateCommand truncates a command to a reasonable length for display
func truncateCommand(cmd string) string {
	const maxLen = 100
	if len(cmd) <= maxLen {
		return cmd
	}
	return cmd[:maxLen] + "..."
}
