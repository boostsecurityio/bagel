// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"errors"
	"io"
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

// defaultMaxLineSize is the safe per-line cap used when the caller passes 0.
// bufio's own default is 64KB, which silently truncates the rest of a file
// the moment it hits a longer line — matching shell_history's 1MB lets us
// handle minified JSON values, long base64 tokens, and the like.
const defaultMaxLineSize = 1024 * 1024

// scanFileLines opens filePath and runs registry.DetectAll against each
// non-empty line, attaching the 1-based line number to every finding so the
// reporter can render a "path:line" location. Returns nil if the file can't
// be opened (logged at debug). Use this for line-oriented formats — INI,
// dotenv, JSONL, URL-per-line credential stores. SSH keys and other
// multi-line PEM blocks must keep their whole-file scan path.
//
// maxLineSize sets the per-line buffer cap; 0 means defaultMaxLineSize.
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

	return scanReaderLines(ctx, "file:"+filePath, file, probeName, registry, maxLineSize)
}

// scanReaderLines is the line-scanning core. Callers that already hold the
// file content in memory (e.g. probes that also need it for misconfig
// parsing) can pass bytes.NewReader(content) here to avoid re-reading the
// file from disk. source identifies the origin and is set verbatim on each
// finding's DetectionContext.Source (typically "file:<path>").
func scanReaderLines(
	ctx context.Context,
	source string,
	r io.Reader,
	probeName string,
	registry *detector.Registry,
	maxLineSize int,
) []models.Finding {
	if maxLineSize <= 0 {
		maxLineSize = defaultMaxLineSize
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	var findings []models.Finding
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    source,
			ProbeName: probeName,
		}).WithLineNumber(lineNum)
		findings = append(findings, registry.DetectAll(line, detCtx)...)
	}
	if err := scanner.Err(); err != nil {
		// ErrTooLong stops the scanner mid-file, so anything after the
		// oversized line is silently missed — bump to warn so users notice.
		if errors.Is(err, bufio.ErrTooLong) {
			log.Ctx(ctx).Warn().
				Err(err).
				Str("source", source).
				Int("max_line_size", maxLineSize).
				Msg("Line exceeded scanner buffer; remainder of source not scanned")
		} else {
			log.Ctx(ctx).Debug().
				Err(err).
				Str("source", source).
				Msg("Error scanning source")
		}
	}
	return findings
}
