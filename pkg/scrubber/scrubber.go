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
	"sync"
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

// sessionDirs lists known AI CLI session log locations relative to $HOME.
var sessionDirs = []sessionDir{
	{RelPath: ".claude/projects", Patterns: []string{"*.jsonl", "*.txt"}},
	{RelPath: ".codex/sessions", Patterns: []string{"*.jsonl"}},
	{RelPath: ".gemini/tmp", Patterns: []string{"*.json"}},
	{RelPath: ".local/share/opencode/storage", Patterns: []string{"*.json"}},
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

// RunInput configures a scrub run.
type RunInput struct {
	Confirm      bool
	GraceMinutes int
	File         string
}

// RunResult holds the outcome of a scrub run.
type RunResult struct {
	FilesScanned  int
	FilesModified int
	Redactions    int
	CountsByType  map[string]int
}

// fileResult holds the outcome of processing a single file.
type fileResult struct {
	changed bool
	counts  map[string]int
}

// Run orchestrates a full scrub operation. When Confirm is false,
// files are scanned but not modified (dry run). Files are processed
// concurrently for performance.
func Run(ctx context.Context, input RunInput) (RunResult, error) {
	log := zerolog.Ctx(ctx)
	result := RunResult{CountsByType: make(map[string]int)}

	var files []string
	if input.File != "" {
		if _, err := os.Stat(input.File); err != nil {
			return result, fmt.Errorf("file not found: %s", input.File)
		}
		files = []string{input.File}
	} else {
		var err error
		files, err = FindEligibleFiles(ctx, input.GraceMinutes)
		if err != nil {
			return result, fmt.Errorf("find files: %w", err)
		}
	}

	result.FilesScanned = len(files)

	if len(files) == 0 {
		log.Info().
			Int("grace_minutes", input.GraceMinutes).
			Msg("No eligible files found")
		return result, nil
	}

	log.Debug().
		Int("file_count", len(files)).
		Msg("Found eligible files")

	// Process files concurrently
	workers := runtime.GOMAXPROCS(0)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	var mu sync.Mutex

	for _, path := range files {
		g.Go(func() error {
			if ctx.Err() != nil {
				return nil // context cancelled
			}

			fr, err := processFile(path, input.Confirm)
			if err != nil {
				log.Warn().Err(err).Str("file", path).Msg("Failed to process file")
				return nil // don't abort other files
			}

			if !fr.changed {
				return nil
			}

			mu.Lock()
			result.FilesModified++
			mergeCounts(result.CountsByType, fr.counts)
			result.Redactions += sumCounts(fr.counts)
			mu.Unlock()

			mode := "Scrubbed"
			if !input.Confirm {
				mode = "[DRY] Would scrub"
			}
			log.Debug().
				Str("file", filepath.Base(path)).
				Str("types", formatCounts(fr.counts)).
				Msg(mode)

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return result, fmt.Errorf("process files: %w", err)
	}

	return result, nil
}

// processFile handles a single file in either confirm or dry-run mode.
func processFile(path string, confirm bool) (fileResult, error) {
	if confirm {
		changed, counts, err := ScrubFile(path)
		if err != nil {
			return fileResult{}, err
		}
		return fileResult{changed: changed, counts: counts}, nil
	}

	// Dry-run: read and check without writing
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
