// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package fileindex

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charlievieth/fastwalk"
	"github.com/rs/zerolog/log"
)

// FileIndex holds matched file paths grouped by pattern name.
type FileIndex struct {
	mu      sync.RWMutex
	entries map[string][]string
}

func NewFileIndex() *FileIndex {
	return &FileIndex{entries: make(map[string][]string)}
}

func (fi *FileIndex) Add(patternName, filePath string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.entries[patternName] = append(fi.entries[patternName], filePath)
}

func (fi *FileIndex) Get(patternName string) []string {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	paths := fi.entries[patternName]
	if paths == nil {
		return []string{}
	}
	result := make([]string, len(paths))
	copy(result, paths)
	return result
}

func (fi *FileIndex) GetAll() map[string][]string {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	result := make(map[string][]string, len(fi.entries))
	for k, v := range fi.entries {
		paths := make([]string, len(v))
		copy(paths, v)
		result[k] = paths
	}
	return result
}

func (fi *FileIndex) TotalFiles() int {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	count := 0
	for _, paths := range fi.entries {
		count += len(paths)
	}
	return count
}

type PatternType string

const (
	PatternTypeGlob  PatternType = "glob"
	PatternTypeExact PatternType = "exact"
	PatternTypeRegex PatternType = "regex"
)

type Pattern struct {
	Name     string
	Patterns []string
	Type     PatternType
}

type patternMatcher func(basename, relPath string) bool

type compiledPattern struct {
	name     string
	matchers []patternMatcher
}

func compilePatterns(patterns []Pattern) []compiledPattern {
	out := make([]compiledPattern, 0, len(patterns))
	for _, p := range patterns {
		cp := compiledPattern{
			name:     p.Name,
			matchers: make([]patternMatcher, 0, len(p.Patterns)),
		}
		for _, raw := range p.Patterns {
			cp.matchers = append(cp.matchers, compilePattern(p.Type, raw))
		}
		out = append(out, cp)
	}
	return out
}

// compilePattern classifies a raw entry into its minimum-cost matcher: exact,
// basename glob, literal path (suffix match at any depth), or anchored path glob.
func compilePattern(kind PatternType, pat string) patternMatcher {
	switch kind {
	case PatternTypeExact:
		// Normalize the pattern's separators so a config-supplied path like
		// ".config/git/config" matches the OS-native relPath on Windows
		// (filepath.Rel returns paths with '\').
		normalized := filepath.FromSlash(pat)
		return func(basename, relPath string) bool {
			return relPath == normalized || basename == normalized
		}
	case PatternTypeGlob:
		if !strings.Contains(pat, "/") {
			if _, err := filepath.Match(pat, ""); err != nil {
				return func(string, string) bool { return false }
			}
			return func(basename, _ string) bool {
				matched, _ := filepath.Match(pat, basename)
				return matched
			}
		}
		// Normalize to the OS separator so filepath.Match / HasSuffix work on
		// Windows, where filepath.Rel returns paths with '\' but configs use '/'.
		normalized := filepath.FromSlash(pat)
		if !strings.ContainsAny(pat, "*?[") {
			return func(_, relPath string) bool {
				return relPath == normalized || strings.HasSuffix(relPath, normalized)
			}
		}
		if _, err := filepath.Match(normalized, ""); err != nil {
			return func(string, string) bool { return false }
		}
		return func(_, relPath string) bool {
			matched, _ := filepath.Match(normalized, relPath)
			return matched
		}
	default:
		return func(string, string) bool { return false }
	}
}

// excludeSet holds normalized ExcludePaths. Entries classified as bare
// basenames prune any directory at any depth whose name matches
// (e.g. "node_modules"); concrete paths prune that specific tree.
type excludeSet struct {
	paths     []string
	basenames map[string]struct{}
}

func newExcludeSet(entries []string) excludeSet {
	set := excludeSet{basenames: make(map[string]struct{})}
	for _, p := range entries {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		expanded := expandHomeDir(trimmed)
		if expanded == "" {
			continue
		}
		cleaned := filepath.Clean(filepath.FromSlash(expanded))
		if cleaned == "" || cleaned == "." {
			continue
		}
		if !filepath.IsAbs(cleaned) && !strings.ContainsRune(cleaned, os.PathSeparator) {
			set.basenames[cleaned] = struct{}{}
			continue
		}
		set.paths = append(set.paths, cleaned)
	}
	return set
}

func (s excludeSet) excludes(dir string) bool {
	if len(s.basenames) > 0 {
		if _, ok := s.basenames[filepath.Base(dir)]; ok {
			return true
		}
	}
	if len(s.paths) == 0 {
		return false
	}
	cleaned := filepath.Clean(dir)
	for _, excluded := range s.paths {
		if cleaned == excluded {
			return true
		}
		rel, err := filepath.Rel(excluded, cleaned)
		if err != nil {
			continue
		}
		// filepath.Rel returns ".." or "../..." iff cleaned is outside excluded.
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

type BuildIndexInput struct {
	BaseDirs         []string
	ExcludePaths     []string
	Patterns         []Pattern
	MaxDepth         int // 0 = unlimited
	FollowSymlinks   bool
	NumWorkers       int // fastwalk workers; 0 = library default
	ProgressCallback func(processed int64)
}

func BuildIndex(ctx context.Context, input BuildIndexInput) (*FileIndex, error) {
	index := NewFileIndex()

	expandedDirs := make([]string, 0, len(input.BaseDirs))
	for _, dir := range input.BaseDirs {
		expandedDirs = append(expandedDirs, expandHomeDir(dir))
	}

	excludes := newExcludeSet(input.ExcludePaths)
	compiled := compilePatterns(input.Patterns)

	log.Ctx(ctx).Info().
		Strs("base_dirs", expandedDirs).
		Int("pattern_count", len(input.Patterns)).
		Int("max_depth", input.MaxDepth).
		Bool("follow_symlinks", input.FollowSymlinks).
		Int("exclude_path_count", len(excludes.paths)).
		Int("exclude_basename_count", len(excludes.basenames)).
		Msg("Building file index")

	var filesProcessed atomic.Int64

	progressDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				processed := filesProcessed.Load()
				if input.ProgressCallback != nil {
					input.ProgressCallback(processed)
				}
				log.Ctx(ctx).Debug().
					Int64("files_processed", processed).
					Msg("File index build progress")
			case <-progressDone:
				return
			}
		}
	}()

	// fastwalk's MaxDepth stops recursion when a directory's own depth
	// equals MaxDepth, so files at that depth aren't enumerated. Our API
	// means "process files up to and including this depth", so pass +1.
	cfg := fastwalk.Config{Follow: input.FollowSymlinks, NumWorkers: input.NumWorkers}
	if input.MaxDepth > 0 {
		cfg.MaxDepth = input.MaxDepth + 1
	}

	var baseDirWg sync.WaitGroup
	for _, baseDir := range expandedDirs {
		baseDirWg.Add(1)
		go func(baseDir string) {
			defer baseDirWg.Done()
			walkBaseDir(ctx, baseDir, cfg, compiled, excludes, index, &filesProcessed)
		}(baseDir)
	}
	baseDirWg.Wait()
	close(progressDone)

	if err := ctx.Err(); err != nil {
		return index, fmt.Errorf("build file index: %w", err)
	}

	totalFiles := index.TotalFiles()
	log.Ctx(ctx).Info().
		Int("total_files", totalFiles).
		Int64("files_processed", filesProcessed.Load()).
		Msg("File index build complete")

	return index, nil
}

func walkBaseDir(
	ctx context.Context,
	baseDir string,
	cfg fastwalk.Config,
	patterns []compiledPattern,
	excludes excludeSet,
	index *FileIndex,
	filesProcessed *atomic.Int64,
) {
	info, err := os.Stat(baseDir)
	if err != nil {
		log.Ctx(ctx).Warn().
			Err(err).
			Str("base_dir", baseDir).
			Msg("Skipping inaccessible base directory")
		return
	}
	if !info.IsDir() {
		log.Ctx(ctx).Warn().
			Str("base_dir", baseDir).
			Msg("Skipping non-directory base path")
		return
	}

	walkFn := func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}

		if walkErr != nil {
			// fastwalk invokes walkFn a second time with a non-nil err when
			// readDir failed; returning SkipDir would escape as Walk's final
			// error. Returning nil is correct — fastwalk already skips.
			log.Ctx(ctx).Debug().
				Err(walkErr).
				Str("path", path).
				Msg("Skipping path due to walk error")
			return nil
		}

		if d.IsDir() {
			if excludes.excludes(path) {
				log.Ctx(ctx).Debug().
					Str("dir", path).
					Msg("Skipping excluded directory")
				return filepath.SkipDir
			}
			return nil
		}

		matchFile(ctx, baseDir, path, patterns, index)
		filesProcessed.Add(1)
		return nil
	}

	if err := fastwalk.Walk(&cfg, baseDir, walkFn); err != nil {
		if ctx.Err() == nil {
			log.Ctx(ctx).Warn().
				Err(err).
				Str("base_dir", baseDir).
				Msg("fastwalk returned error")
		}
	}
}

func matchFile(ctx context.Context, baseDir string, filePath string, patterns []compiledPattern, index *FileIndex) {
	relPath, err := filepath.Rel(baseDir, filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Str("base_dir", baseDir).
			Msg("Cannot get relative path")
		return
	}
	basename := filepath.Base(filePath)

	for _, pattern := range patterns {
		for _, m := range pattern.matchers {
			if m(basename, relPath) {
				index.Add(pattern.name, filePath)
				log.Ctx(ctx).Debug().
					Str("pattern", pattern.name).
					Str("file", filePath).
					Msg("File matched pattern")
				break
			}
		}
	}
}

func expandHomeDir(path string) string {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.Replace(path, "~", home, 1)
		}
	}
	if strings.Contains(path, "$HOME") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.ReplaceAll(path, "$HOME", home)
		}
	}
	if runtime.GOOS == "windows" && strings.Contains(path, "%USERPROFILE%") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.ReplaceAll(path, "%USERPROFILE%", home)
		}
	}
	return os.ExpandEnv(path)
}
