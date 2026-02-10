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
	"golang.org/x/sync/errgroup"
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

// fileEntry represents a discovered file to be processed by workers
type fileEntry struct {
	baseDir  string
	filePath string
}

// BuildIndexInput holds the input parameters for building a file index
type BuildIndexInput struct {
	BaseDirs         []string              // Base directories to search (e.g., ["$HOME"])
	Patterns         []Pattern             // Patterns to match
	MaxDepth         int                   // Maximum recursion depth (0 = unlimited)
	FollowSymlinks   bool                  // Whether to follow symbolic links
	ProgressCallback func(processed int64) // Optional progress reporter
}

// BuildIndex recursively scans directories and builds a file index using concurrent workers
func BuildIndex(ctx context.Context, input BuildIndexInput) (*FileIndex, error) {
	index := NewFileIndex()

	// Expand environment variables in base directories
	expandedDirs := make([]string, 0, len(input.BaseDirs))
	for _, dir := range input.BaseDirs {
		expanded := expandHomeDir(dir)
		expandedDirs = append(expandedDirs, expanded)
	}

	numWorkers := runtime.NumCPU()
	log.Ctx(ctx).Info().
		Strs("base_dirs", expandedDirs).
		Int("pattern_count", len(input.Patterns)).
		Int("max_depth", input.MaxDepth).
		Bool("follow_symlinks", input.FollowSymlinks).
		Int("num_workers", numWorkers).
		Msg("Building file index")

	// Channel for discovered files
	filesChan := make(chan fileEntry, numWorkers*100)

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

	// Use errgroup for coordinated cancellation
	g, gctx := errgroup.WithContext(ctx)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			runWorker(gctx, filesChan, input.Patterns, index, &filesProcessed)
			return nil
		})
	}

	// Start discovery goroutines - one per base directory
	discoveryGroup, discoveryCtx := errgroup.WithContext(gctx)
	for _, baseDir := range expandedDirs {
		discoveryGroup.Go(func() error {
			return runDiscovery(discoveryCtx, baseDir, input, filesChan)
		})
	}

	// Wait for all discovery to complete, then close channel
	go func() {
		_ = discoveryGroup.Wait()
		close(filesChan)
	}()

	// Wait for workers to finish
	if err := g.Wait(); err != nil {
		close(progressDone)
		return nil, fmt.Errorf("file index build failed: %w", err)
	}

	close(progressDone)

	totalFiles := index.TotalFiles()
	log.Ctx(ctx).Info().
		Int("total_files", totalFiles).
		Int64("files_processed", filesProcessed.Load()).
		Msg("File index build complete")

	return index, nil
}

// runDiscovery validates a base directory and starts file discovery
func runDiscovery(ctx context.Context, baseDir string, input BuildIndexInput, filesChan chan<- fileEntry) error {
	// Check if base directory exists and is accessible
	info, err := os.Stat(baseDir)
	if err != nil {
		log.Ctx(ctx).Warn().
			Err(err).
			Str("base_dir", baseDir).
			Msg("Skipping inaccessible base directory")
		return nil
	}

	if !info.IsDir() {
		log.Ctx(ctx).Warn().
			Str("base_dir", baseDir).
			Msg("Skipping non-directory base path")
		return nil
	}

	return walkDirectory(ctx, baseDir, baseDir, input, filesChan, 0)
}

// runWorker processes files from the channel and matches them against patterns
func runWorker(ctx context.Context, filesChan <-chan fileEntry, patterns []Pattern, index *FileIndex, filesProcessed *atomic.Int64) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-filesChan:
			if !ok {
				return
			}
			matchFile(ctx, entry.baseDir, entry.filePath, patterns, index)
			filesProcessed.Add(1)
		}
	}
}

// walkDirectory recursively walks a directory and sends discovered files to the channel
func walkDirectory(
	ctx context.Context,
	baseDir string,
	currentDir string,
	input BuildIndexInput,
	filesChan chan<- fileEntry,
	depth int,
) error {
	// Check depth limit
	if input.MaxDepth > 0 && depth > input.MaxDepth {
		return nil
	}

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled: %w", ctx.Err())
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
		return nil
	}

	for _, entry := range entries {
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
				// Recursively walk symlinked directory
				if err := walkDirectory(ctx, baseDir, resolvedPath, input, filesChan, depth+1); err != nil {
					return err
				}
			} else {
				// Send symlinked file to channel
				select {
				case <-ctx.Done():
					return fmt.Errorf("context cancelled: %w", ctx.Err())
				case filesChan <- fileEntry{baseDir: baseDir, filePath: resolvedPath}:
				}
			}
			continue
		}

		// Handle directories
		if entry.IsDir() {
			if err := walkDirectory(ctx, baseDir, fullPath, input, filesChan, depth+1); err != nil {
				return err
			}
			continue
		}

		// Send file to channel
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled: %w", ctx.Err())
		case filesChan <- fileEntry{baseDir: baseDir, filePath: fullPath}:
		}
	}

	return nil
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
