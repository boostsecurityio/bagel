// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// readMaxFileSizeFlag pulls "max_file_size" out of probe flags, falling back
// to the supplied default. Shared by AICredentialsProbe and AIChatsProbe.
//
// Non-positive or wrong-typed values fall back to the default — a zero or
// negative cap would cause scanAIFile to skip every file (since any file
// size is greater than zero), which is almost certainly a misconfiguration
// rather than an intentional disable. Use the probe's own enabled flag to
// turn it off.
func readMaxFileSizeFlag(flags map[string]interface{}, fallback int64) int64 {
	v, ok := flags["max_file_size"]
	if !ok {
		return fallback
	}
	var size int64
	switch val := v.(type) {
	case int:
		size = int64(val)
	case int64:
		size = val
	case float64:
		size = int64(val)
	default:
		return fallback
	}
	if size <= 0 {
		log.Debug().
			Int64("configured", size).
			Int64("fallback", fallback).
			Msg("max_file_size must be positive; using default")
		return fallback
	}
	return size
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
