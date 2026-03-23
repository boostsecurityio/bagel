// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package fileindex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// FileIndex holds the results of the file system scan
type FileIndex struct {
	mu      sync.RWMutex
	entries map[string][]string // pattern name -> matched file paths
}

// NewFileIndex creates a new empty file index
func NewFileIndex() *FileIndex {
	return &FileIndex{
		entries: make(map[string][]string),
	}
}

// Add adds a matched file path for a given pattern name
func (fi *FileIndex) Add(patternName, filePath string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.entries[patternName] = append(fi.entries[patternName], filePath)
}

// Get retrieves all file paths matching a pattern name
func (fi *FileIndex) Get(patternName string) []string {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	// Return a copy to prevent external modification
	paths := fi.entries[patternName]
	if paths == nil {
		return []string{}
	}

	result := make([]string, len(paths))
	copy(result, paths)
	return result
}

// GetAll returns all indexed files grouped by pattern name
func (fi *FileIndex) GetAll() map[string][]string {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	// Return a deep copy
	result := make(map[string][]string, len(fi.entries))
	for k, v := range fi.entries {
		paths := make([]string, len(v))
		copy(paths, v)
		result[k] = paths
	}
	return result
}

// TotalFiles returns the total number of indexed files
func (fi *FileIndex) TotalFiles() int {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	count := 0
	for _, paths := range fi.entries {
		count += len(paths)
	}
	return count
}

// PatternType defines the type of pattern matching to use
type PatternType string

const (
	PatternTypeGlob  PatternType = "glob"
	PatternTypeExact PatternType = "exact"
	PatternTypeRegex PatternType = "regex" // Reserved for future use
)

// Pattern defines a file pattern to search for
type Pattern struct {
	Name     string      // Unique identifier for this pattern (e.g., "ssh_config")
	Patterns []string    // List of patterns to match (e.g., [".ssh/config", ".ssh/config.d/*"])
	Type     PatternType // Type of pattern matching
}

// BuildIndexInput holds the input parameters for building a file index
type BuildIndexInput struct {
	BaseDirs         []string              // Base directories to search (e.g., ["$HOME"])
	ExcludePaths     []string              // Paths to skip entirely (e.g., ["~/repos", "~/.cache"])
	Patterns         []Pattern             // Patterns to match
	MaxDepth         int                   // Maximum recursion depth (0 = unlimited)
	FollowSymlinks   bool                  // Whether to follow symbolic links
	ProgressCallback func(processed int64) // Optional progress reporter
}

// BuildIndex recursively scans directories and builds a file index with inline matching
func BuildIndex(ctx context.Context, input BuildIndexInput) (*FileIndex, error) {
	index := NewFileIndex()

	// Expand environment variables in base directories
	expandedDirs := make([]string, 0, len(input.BaseDirs))
	for _, dir := range input.BaseDirs {
		expanded := expandHomeDir(dir)
		expandedDirs = append(expandedDirs, expanded)
	}

	// Expand and normalize exclude paths so that inputs like "~/repos/" or
	// Windows forward-slash paths match correctly inside isExcludedPath.
	expandedExcludes := make([]string, 0, len(input.ExcludePaths))
	for _, p := range input.ExcludePaths {
		expanded := expandHomeDir(p)
		if expanded != "" {
			expanded = filepath.Clean(filepath.FromSlash(expanded))
		}
		expandedExcludes = append(expandedExcludes, expanded)
	}
	input.ExcludePaths = expandedExcludes

	log.Ctx(ctx).Info().
		Strs("base_dirs", expandedDirs).
		Int("pattern_count", len(input.Patterns)).
		Int("max_depth", input.MaxDepth).
		Bool("follow_symlinks", input.FollowSymlinks).
		Msg("Building file index")

	// Counter for progress reporting
	var filesProcessed atomic.Int64

	// Start progress reporter
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

	// Discovery — one goroutine per base dir, each runs parallel walkers internally
	var discoveryWg sync.WaitGroup
	for _, baseDir := range expandedDirs {
		discoveryWg.Add(1)
		go func(dir string) {
			defer discoveryWg.Done()
			runDiscovery(ctx, dir, input, index, &filesProcessed)
		}(baseDir)
	}

	discoveryWg.Wait()
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

// runDiscovery validates a base directory and starts file discovery with inline matching
func runDiscovery(
	ctx context.Context,
	baseDir string,
	input BuildIndexInput,
	index *FileIndex,
	filesProcessed *atomic.Int64,
) {
	// Check if base directory exists and is accessible
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

	// Create semaphore and WaitGroup for parallel subdirectory traversal (GDU-style)
	sem := make(chan struct{}, 3*runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup

	walkDirectory(ctx, baseDir, baseDir, input, input.Patterns, index, filesProcessed, 0, sem, &wg)

	// Wait for all spawned goroutines to finish before returning
	wg.Wait()
}

// walkDirectory recursively walks a directory and matches discovered files inline.
// Subdirectories are traversed in parallel using goroutines gated by the semaphore (GDU-style).
func walkDirectory(
	ctx context.Context,
	baseDir string,
	currentDir string,
	input BuildIndexInput,
	patterns []Pattern,
	index *FileIndex,
	filesProcessed *atomic.Int64,
	depth int,
	sem chan struct{},
	wg *sync.WaitGroup,
) {
	// Check depth limit
	if input.MaxDepth > 0 && depth > input.MaxDepth {
		return
	}

	// Check if current directory is excluded
	if isExcludedPath(currentDir, input.ExcludePaths) {
		log.Ctx(ctx).Debug().
			Str("dir", currentDir).
			Msg("Skipping excluded directory")
		return
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Read directory entries
	entries, err := os.ReadDir(currentDir)
	if err != nil {
		// Permission denied or other errors - log and continue
		log.Ctx(ctx).Debug().
			Err(err).
			Str("dir", currentDir).
			Msg("Cannot read directory")
		return
	}

	for _, entry := range entries {
		// Check cancellation each iteration for responsive shutdown
		select {
		case <-ctx.Done():
			return
		default:
		}

		fullPath := filepath.Join(currentDir, entry.Name())

		// Handle symbolic links
		if entry.Type()&os.ModeSymlink != 0 {
			if !input.FollowSymlinks {
				continue
			}

			// Resolve symlink
			resolvedPath, err := filepath.EvalSymlinks(fullPath)
			if err != nil {
				log.Ctx(ctx).Debug().
					Err(err).
					Str("symlink", fullPath).
					Msg("Cannot resolve symlink")
				continue
			}

			// Check if it's a directory
			resolvedInfo, err := os.Stat(resolvedPath)
			if err != nil {
				continue
			}

			if resolvedInfo.IsDir() {
				select {
				case sem <- struct{}{}:
					wg.Add(1)
					go func(path string) {
						defer wg.Done()
						defer func() { <-sem }()
						walkDirectory(ctx, baseDir, path, input, patterns, index, filesProcessed, depth+1, sem, wg)
					}(resolvedPath)
				case <-ctx.Done():
					return
				default:
					// Semaphore full - recurse inline to avoid deadlock
					walkDirectory(ctx, baseDir, resolvedPath, input, patterns, index, filesProcessed, depth+1, sem, wg)
				}
			} else {
				// Match symlinked file inline
				matchFile(ctx, baseDir, resolvedPath, patterns, index)
				filesProcessed.Add(1)
			}
			continue
		}

		// Handle directories
		if entry.IsDir() {
			select {
			case sem <- struct{}{}:
				wg.Add(1)
				go func(path string) {
					defer wg.Done()
					defer func() { <-sem }()
					walkDirectory(ctx, baseDir, path, input, patterns, index, filesProcessed, depth+1, sem, wg)
				}(fullPath)
			case <-ctx.Done():
				return
			default:
				// Semaphore full - recurse inline to avoid deadlock
				walkDirectory(ctx, baseDir, fullPath, input, patterns, index, filesProcessed, depth+1, sem, wg)
			}
			continue
		}

		// Match file inline
		matchFile(ctx, baseDir, fullPath, patterns, index)
		filesProcessed.Add(1)
	}
}

// isExcludedPath reports whether path should be skipped during file index building.
// A path is excluded if it equals any entry in excludePaths, or is a child of one.
// excludePaths must already be expanded and normalized (no ~ or $HOME variables).
func isExcludedPath(path string, excludePaths []string) bool {
	cleanedPath := filepath.Clean(path)
	for _, excluded := range excludePaths {
		trimmed := strings.TrimSpace(excluded)
		if trimmed == "" {
			continue
		}
		cleanedExcluded := filepath.Clean(trimmed)
		if cleanedPath == cleanedExcluded || strings.HasPrefix(cleanedPath, cleanedExcluded+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// expandHomeDir expands $HOME, %USERPROFILE%, and ~ to the user's home directory.
// Falls back to os.ExpandEnv for other environment variables.
func expandHomeDir(path string) string {
	// Handle ~ prefix
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.Replace(path, "~", home, 1)
		}
	}

	// Handle $HOME (Unix) - os.ExpandEnv won't work on Windows
	if strings.Contains(path, "$HOME") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.ReplaceAll(path, "$HOME", home)
		}
	}

	// Handle %USERPROFILE% (Windows) - os.ExpandEnv handles this, but be explicit
	if runtime.GOOS == "windows" && strings.Contains(path, "%USERPROFILE%") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = strings.ReplaceAll(path, "%USERPROFILE%", home)
		}
	}

	// Expand remaining environment variables
	return os.ExpandEnv(path)
}

// matchFile checks if a file matches any of the patterns and adds it to the index
func matchFile(ctx context.Context, baseDir string, filePath string, patterns []Pattern, index *FileIndex) {
	// Get relative path from base directory
	relPath, err := filepath.Rel(baseDir, filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Str("base_dir", baseDir).
			Msg("Cannot get relative path")
		return
	}

	// Check against all patterns
	for _, pattern := range patterns {
		for _, pat := range pattern.Patterns {
			matched := false

			switch pattern.Type {
			case PatternTypeGlob:
				// Use filepath.Match for glob patterns
				matched, err = filepath.Match(pat, filepath.Base(filePath))
				if err != nil {
					log.Ctx(ctx).Debug().
						Err(err).
						Str("pattern", pat).
						Msg("Invalid glob pattern")
					continue
				}

				// Also check if the relative path matches the pattern exactly
				if !matched {
					matched, _ = filepath.Match(pat, relPath)
				}

				// For patterns with path separators, check if relPath ends with the pattern
				if !matched && strings.Contains(pat, "/") {
					// Convert to OS-specific path separator
					normalizedPattern := filepath.FromSlash(pat)
					normalizedRelPath := filepath.FromSlash(relPath)

					// Check if the relative path ends with the pattern
					if strings.HasSuffix(normalizedRelPath, normalizedPattern) {
						matched = true
					} else {
						// Also try direct filepath.Match in case it's a glob with wildcards
						matched, _ = filepath.Match(normalizedPattern, normalizedRelPath)
					}
				}

			case PatternTypeExact:
				// Exact match against relative path or basename
				matched = relPath == pat || filepath.Base(filePath) == pat
			}

			if matched {
				index.Add(pattern.Name, filePath)
				log.Ctx(ctx).Debug().
					Str("pattern", pattern.Name).
					Str("file", filePath).
					Msg("File matched pattern")
				break // Don't match the same file multiple times for the same pattern
			}
		}
	}
}
