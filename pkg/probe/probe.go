// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// Probe defines the interface that all probes must implement
type Probe interface {
	// Name returns the name of the probe (e.g., "git", "ssh", "npm")
	Name() string

	// Execute runs the probe and returns findings
	Execute(ctx context.Context) ([]models.Finding, error)

	// IsEnabled returns whether the probe is enabled
	IsEnabled() bool
}

// FileIndexAware is an optional interface that probes can implement
// to receive the pre-built file index before execution
type FileIndexAware interface {
	// SetFileIndex provides the file index to the probe
	SetFileIndex(index *fileindex.FileIndex)
}

// FingerprintSaltAware is an optional interface that probes can implement
// to receive the machine-specific fingerprint salt before execution
type FingerprintSaltAware interface {
	// SetFingerprintSalt provides the fingerprint salt to the probe
	SetFingerprintSalt(salt string)
}

// Result represents the output of a probe execution
type Result struct {
	ProbeName string
	Findings  []models.Finding
	Error     error
}

// scanFileLines opens filePath and runs registry.DetectAll against each
// non-empty line, attaching the 1-based line number to every finding so the
// reporter can render a "path:line" location. Returns nil if the file can't
// be opened (logged at debug). Use this for line-oriented formats — INI,
// dotenv, JSONL, URL-per-line credential stores. SSH keys and other
// multi-line PEM blocks must keep their whole-file scan path.
//
// maxLineSize sets the scanner's per-line buffer cap; 0 keeps bufio's
// default (64KB).
func scanFileLines(
	ctx context.Context,
	filePath string,
	probeName string,
	registry *detector.Registry,
	maxLineSize int,
) []models.Finding {
	file, err := os.Open(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot open file for line scan")
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if maxLineSize > 0 {
		scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	}

	var findings []models.Finding
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "file:" + filePath,
			ProbeName: probeName,
		}).WithLineNumber(lineNum)
		findings = append(findings, registry.DetectAll(line, detCtx)...)
	}
	if err := scanner.Err(); err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Error scanning file")
	}
	return findings
}
