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
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// patterns is initialized once and reused across all scrub operations.
var patterns = Patterns()

// ScrubContent applies all credential patterns to content.
// Returns the scrubbed text and a map of label -> match count.
// Uses prefix checks to skip regexes that cannot match.
func ScrubContent(content string) (string, map[string]int) {
	counts := make(map[string]int)
	for _, p := range patterns {
		if !containsAny(content, p.Prefixes) {
			continue
		}
		matches := p.Regex.FindAllString(content, -1)
		if len(matches) > 0 {
			counts[p.Label] += len(matches)
			content = p.Regex.ReplaceAllString(content, p.Replacement)
		}
	}
	return content, counts
}

// sessionDir defines an AI CLI session directory and its file globs.
type sessionDir struct {
	RelPath  string
	Patterns []string
}

// sessionDirs lists known AI CLI session log and shell history
// locations relative to $HOME. An empty RelPath means files live
// directly in $HOME (matched by name, not walked recursively).
var sessionDirs = []sessionDir{
	{RelPath: ".claude/projects", Patterns: []string{"*.jsonl", "*.txt"}},
	{RelPath: ".codex/sessions", Patterns: []string{"*.jsonl"}},
	{RelPath: ".gemini/tmp", Patterns: []string{"*.json"}},
	{RelPath: ".local/share/opencode/storage", Patterns: []string{"*.json"}},
	{RelPath: "", Patterns: []string{".bash_history", ".zsh_history", ".sh_history"}},
	{RelPath: ".local/share/fish", Patterns: []string{"fish_history"}},
}

// FindEligibleFiles walks known AI CLI paths and returns files older
// than graceMins minutes. Files modified within the grace period are
// skipped to avoid interfering with active sessions.
func FindEligibleFiles(ctx context.Context, graceMins int) ([]string, error) {
	log := zerolog.Ctx(ctx)

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	cutoff := time.Now().Add(-time.Duration(graceMins) * time.Minute)
	var files []string

	for _, sd := range sessionDirs {
		if sd.RelPath == "" {
			// Direct file lookup in $HOME (no recursive walk).
			for _, name := range sd.Patterns {
				path := filepath.Join(home, name)
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if info.ModTime().Before(cutoff) {
					files = append(files, path)
				}
			}
			continue
		}

		base := filepath.Join(home, sd.RelPath)
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}

		for _, glob := range sd.Patterns {
			err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					log.Warn().Err(err).Str("path", path).Msg("Skipping unreadable entry")
					return nil
				}
				if info.IsDir() {
					return nil
				}
				matched, _ := filepath.Match(glob, info.Name())
				if !matched {
					return nil
				}
				if info.ModTime().Before(cutoff) {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("walk %s: %w", base, err)
			}
		}
	}

	return files, nil
}

// ScrubFile reads a file, scrubs its content, and writes it back.
// Returns whether the file was modified and counts by label.
func ScrubFile(path string) (bool, map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read %s: %w", path, err)
	}

	content := string(data)

	// Fast path: skip files with no potential secrets
	if !MightContainSecrets(content) {
		return false, nil, nil
	}

	scrubbed, counts := ScrubContent(content)

	if scrubbed == content {
		return false, counts, nil
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

// ScanInput configures a scrub scan.
type ScanInput struct {
	GraceMinutes int
	File         string
}

// ScanResult holds the outcome of scanning files for credentials.
// Files lists the paths that contain redactable content.
type ScanResult struct {
	FilesScanned int
	Files        []string
	Redactions   int
	CountsByType map[string]int
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

// Scan finds eligible files and counts what would be redacted.
// It never writes to disk.
func Scan(ctx context.Context, input ScanInput) (ScanResult, error) {
	log := zerolog.Ctx(ctx)
	result := ScanResult{CountsByType: make(map[string]int)}

	files, err := resolveFiles(ctx, input)
	if err != nil {
		return result, err
	}

	result.FilesScanned = len(files)
	if len(files) == 0 {
		log.Info().
			Int("grace_minutes", input.GraceMinutes).
			Msg("No eligible files found")
		return result, nil
	}

	log.Debug().Int("file_count", len(files)).Msg("Found eligible files")

	results, err := processFilesConcurrently(ctx, files, scanFile)
	if err != nil {
		return result, err
	}

	for i, fr := range results {
		if !fr.changed {
			continue
		}
		result.Files = append(result.Files, files[i])
		mergeCounts(result.CountsByType, fr.counts)
		result.Redactions += sumCounts(fr.counts)
	}

	return result, nil
}

// Apply scrubs credential patterns from the given files, writing
// changes back to disk. Call Scan first to discover which files
// need scrubbing.
func Apply(ctx context.Context, files []string) (ApplyResult, error) {
	log := zerolog.Ctx(ctx)
	result := ApplyResult{CountsByType: make(map[string]int)}

	if len(files) == 0 {
		return result, nil
	}

	results, err := processFilesConcurrently(ctx, files, applyFile)
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
			Str("file", filepath.Base(files[i])).
			Str("types", formatCounts(fr.counts)).
			Msg("Scrubbed")
	}

	return result, nil
}

func resolveFiles(ctx context.Context, input ScanInput) ([]string, error) {
	if input.File != "" {
		if _, err := os.Stat(input.File); err != nil {
			return nil, fmt.Errorf("file not found: %s", input.File)
		}
		return []string{input.File}, nil
	}
	files, err := FindEligibleFiles(ctx, input.GraceMinutes)
	if err != nil {
		return nil, fmt.Errorf("find files: %w", err)
	}
	return files, nil
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

// scanFile reads a file and checks for redactable content without writing.
func scanFile(path string) (fileResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fileResult{}, fmt.Errorf("read %s: %w", path, err)
	}

	content := string(data)
	if !MightContainSecrets(content) {
		return fileResult{}, nil
	}

	_, counts := ScrubContent(content)
	if len(counts) > 0 {
		return fileResult{changed: true, counts: counts}, nil
	}
	return fileResult{}, nil
}

// applyFile reads a file, scrubs it, and writes the result back.
func applyFile(path string) (fileResult, error) {
	changed, counts, err := ScrubFile(path)
	if err != nil {
		return fileResult{}, err
	}
	return fileResult{changed: changed, counts: counts}, nil
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
