// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package scrubber

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// scrubFile reads a file, applies all registry redactions, and writes back.
// Returns whether the file was modified and counts by label.
func scrubFile(path string, registry *detector.Registry) (bool, map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read %s: %w", path, err)
	}

	content := string(data)
	scrubbed, counts := registry.RedactAll(content)

	if scrubbed == content {
		return false, nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return false, nil, fmt.Errorf("stat %s: %w", path, err)
	}

	if err := os.WriteFile(path, []byte(scrubbed), info.Mode()); err != nil {
		return false, nil, fmt.Errorf("write %s: %w", path, err)
	}

	return true, counts, nil
}

// PreviewInput configures a read-only scrub preview.
type PreviewInput struct {
	Files    []string
	Registry *detector.Registry
}

// PreviewResult holds the outcome of previewing files for redactable content.
// Files lists the paths that contain redactable content.
type PreviewResult struct {
	FilesScanned int
	Files        []string
	Redactions   int
	CountsByType map[string]int
}

// ApplyInput configures a scrub apply operation.
type ApplyInput struct {
	Files    []string
	Registry *detector.Registry
}

// ApplyResult holds the outcome of applying redactions.
type ApplyResult struct {
	FilesModified int
	Redactions    int
	CountsByType  map[string]int
}

// fileResult holds the outcome of processing a single file.
type fileResult struct {
	changed bool
	counts  map[string]int
}

// Preview reads files and counts what would be redacted without writing.
func Preview(ctx context.Context, input PreviewInput) (PreviewResult, error) {
	log := zerolog.Ctx(ctx)
	result := PreviewResult{CountsByType: make(map[string]int)}

	result.FilesScanned = len(input.Files)
	if len(input.Files) == 0 {
		log.Info().Msg("No files to preview")
		return result, nil
	}

	log.Debug().Int("file_count", len(input.Files)).Msg("Previewing files")

	processor := func(path string) (fileResult, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return fileResult{}, fmt.Errorf("read %s: %w", path, err)
		}
		_, counts := input.Registry.RedactAll(string(data))
		if len(counts) > 0 {
			return fileResult{changed: true, counts: counts}, nil
		}
		return fileResult{}, nil
	}

	results, err := processFilesConcurrently(ctx, input.Files, processor)
	if err != nil {
		return result, err
	}

	for i, fr := range results {
		if !fr.changed {
			continue
		}
		result.Files = append(result.Files, input.Files[i])
		mergeCounts(result.CountsByType, fr.counts)
		result.Redactions += sumCounts(fr.counts)
	}

	return result, nil
}

// Apply scrubs credential patterns from the given files, writing
// changes back to disk. Call Preview first to discover which files
// need scrubbing.
func Apply(ctx context.Context, input ApplyInput) (ApplyResult, error) {
	log := zerolog.Ctx(ctx)
	result := ApplyResult{CountsByType: make(map[string]int)}

	if len(input.Files) == 0 {
		return result, nil
	}

	processor := func(path string) (fileResult, error) {
		changed, counts, err := scrubFile(path, input.Registry)
		if err != nil {
			return fileResult{}, err
		}
		return fileResult{changed: changed, counts: counts}, nil
	}

	results, err := processFilesConcurrently(ctx, input.Files, processor)
	if err != nil {
		return result, err
	}

	for i, fr := range results {
		if !fr.changed {
			continue
		}
		result.FilesModified++
		mergeCounts(result.CountsByType, fr.counts)
		result.Redactions += sumCounts(fr.counts)

		log.Debug().
			Str("file", filepath.Base(input.Files[i])).
			Str("types", formatCounts(fr.counts)).
			Msg("Scrubbed")
	}

	return result, nil
}

// fileProcessor is a function that processes a single file and
// returns whether it had redactable content and the counts by type.
type fileProcessor func(path string) (fileResult, error)

func processFilesConcurrently(
	ctx context.Context,
	files []string,
	process fileProcessor,
) ([]fileResult, error) {
	log := zerolog.Ctx(ctx)

	results := make([]fileResult, len(files))
	workers := runtime.GOMAXPROCS(0)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	for i, path := range files {
		g.Go(func() error {
			if ctx.Err() != nil {
				return nil
			}
			fr, err := process(path)
			if err != nil {
				log.Warn().Err(err).Str("file", path).Msg("Failed to process file")
				return nil
			}
			results[i] = fr
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("process files: %w", err)
	}
	return results, nil
}

func mergeCounts(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

func sumCounts(counts map[string]int) int {
	total := 0
	for _, v := range counts {
		total += v
	}
	return total
}

func formatCounts(counts map[string]int) string {
	parts := make([]string, 0, len(counts))
	for k, v := range counts {
		parts = append(parts, fmt.Sprintf("%s:%d", k, v))
	}
	return strings.Join(parts, ", ")
}
