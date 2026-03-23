// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/rs/zerolog"
)

const (
	// SchemaVersion is incremented when the cache format changes.
	// Bumped to 4: added ExcludePaths to Metadata for cache key validation.
	SchemaVersion = 4
	// cacheFilePrefix is the prefix for cache files
	cacheFilePrefix = "fileindex-"
)

// Metadata holds information about the cached file index
type Metadata struct {
	SchemaVersion  int       `json:"schema_version"`
	CreatedAt      time.Time `json:"created_at"`
	BaseDirs       []string  `json:"base_dirs"`     // Stored as expanded paths
	ExcludePaths   []string  `json:"exclude_paths"` // Stored as expanded paths
	PatternsHash   string    `json:"patterns_hash"`
	MaxDepth       int       `json:"max_depth"`
	FollowSymlinks bool      `json:"follow_symlinks"`

	// Staleness detection fields
	BaseDirModTimes map[string]int64  `json:"base_dir_mod_times"` // dir -> mtime (Unix nanoseconds)
	FileSample      []FileSampleEntry `json:"file_sample"`        // Sampled files for validation
	TotalFileCount  int               `json:"total_file_count"`
}

// FileSampleEntry represents a sampled file for staleness validation
type FileSampleEntry struct {
	Path    string `json:"path"`
	ModTime int64  `json:"mod_time"` // Unix nanoseconds
	Size    int64  `json:"size"`
}

// CachedFileIndex represents the serializable form of a file index
type CachedFileIndex struct {
	Metadata Metadata            `json:"metadata"`
	Entries  map[string][]string `json:"entries"` // pattern name -> file paths
}

// Store manages file index caching
type Store struct {
	cacheDir string
}

// NewStore creates a new cache store with the default cache directory
func NewStore() (*Store, error) {
	cacheDir, err := GetCacheDir()
	if err != nil {
		return nil, fmt.Errorf("get cache directory: %w", err)
	}

	return &Store{
		cacheDir: cacheDir,
	}, nil
}

// GetCacheDir returns the platform-specific cache directory for bagel
func GetCacheDir() (string, error) {
	var baseDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home directory: %w", err)
		}
		baseDir = filepath.Join(home, "Library", "Caches", "bagel")
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			return "", errors.New("LOCALAPPDATA environment variable not set")
		}
		baseDir = filepath.Join(localAppData, "bagel", "cache")
	default: // Linux and other Unix-like systems
		xdgCache := os.Getenv("XDG_CACHE_HOME")
		if xdgCache != "" {
			baseDir = filepath.Join(xdgCache, "bagel")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("get home directory: %w", err)
			}
			baseDir = filepath.Join(home, ".cache", "bagel")
		}
	}

	return baseDir, nil
}

// LoadInput holds the parameters for loading a cached file index
type LoadInput struct {
	BaseDirs       []string
	ExcludePaths   []string
	Patterns       []fileindex.Pattern
	MaxDepth       int
	FollowSymlinks bool
	TTL            time.Duration // Cache expiration duration (0 = no TTL check)
	ValidateFiles  bool          // Enable file sample validation
}

// Load attempts to load a cached file index
// Returns nil if the cache doesn't exist or is invalid
func (s *Store) Load(ctx context.Context, input LoadInput) (*fileindex.FileIndex, error) {
	logger := zerolog.Ctx(ctx)

	cacheFile := s.cacheFilePath(cacheKeyInput{
		baseDirs:       input.BaseDirs,
		excludePaths:   input.ExcludePaths,
		patterns:       input.Patterns,
		maxDepth:       input.MaxDepth,
		followSymlinks: input.FollowSymlinks,
	})

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Debug().Str("cache_file", cacheFile).Msg("Cache file not found")
			return nil, nil
		}
		logger.Debug().Err(err).Str("cache_file", cacheFile).Msg("Failed to read cache file")
		return nil, nil
	}

	var cached CachedFileIndex
	if err := json.Unmarshal(data, &cached); err != nil {
		logger.Debug().Err(err).Str("cache_file", cacheFile).Msg("Failed to parse cache file")
		return nil, nil
	}

	// Validate schema version
	if cached.Metadata.SchemaVersion != SchemaVersion {
		logger.Debug().
			Int("cached_version", cached.Metadata.SchemaVersion).
			Int("current_version", SchemaVersion).
			Msg("Cache schema version mismatch")
		return nil, nil
	}

	// Validate patterns hash
	expectedHash := computePatternsHash(input.Patterns)
	if cached.Metadata.PatternsHash != expectedHash {
		logger.Debug().
			Str("cached_hash", cached.Metadata.PatternsHash).
			Str("expected_hash", expectedHash).
			Msg("Cache patterns hash mismatch")
		return nil, nil
	}

	// Validate base dirs match (compare expanded paths)
	expandedInputDirs := ExpandBaseDirs(input.BaseDirs)
	if !slicesEqual(cached.Metadata.BaseDirs, expandedInputDirs) {
		logger.Debug().Msg("Cache base directories mismatch")
		return nil, nil
	}

	// Validate MaxDepth matches
	if cached.Metadata.MaxDepth != input.MaxDepth {
		logger.Debug().
			Int("cached_max_depth", cached.Metadata.MaxDepth).
			Int("expected_max_depth", input.MaxDepth).
			Msg("Cache max depth mismatch")
		return nil, nil
	}

	// Validate FollowSymlinks matches
	if cached.Metadata.FollowSymlinks != input.FollowSymlinks {
		logger.Debug().
			Bool("cached_follow_symlinks", cached.Metadata.FollowSymlinks).
			Bool("expected_follow_symlinks", input.FollowSymlinks).
			Msg("Cache follow symlinks mismatch")
		return nil, nil
	}

	// Validate ExcludePaths match (compare fully normalized, sorted paths)
	sortedCachedExcludes := sortedCopy(cached.Metadata.ExcludePaths)
	sortedInputExcludes := sortedCopy(normalizeExcludePaths(input.ExcludePaths))
	if !slicesEqual(sortedCachedExcludes, sortedInputExcludes) {
		logger.Debug().Msg("Cache exclude paths mismatch")
		return nil, nil
	}

	// Check for cache staleness
	stalenessResult := checkStaleness(StalenessCheckInput{
		Metadata:      cached.Metadata,
		TTL:           input.TTL,
		ValidateFiles: input.ValidateFiles,
	})
	if stalenessResult.IsStale {
		logger.Info().
			Str("reason", stalenessResult.Reason).
			Str("details", stalenessResult.Details).
			Msg("Cache is stale, will rebuild")
		return nil, nil
	}

	// Convert to FileIndex
	index := fileindex.NewFileIndex()
	for patternName, paths := range cached.Entries {
		for _, path := range paths {
			index.Add(patternName, path)
		}
	}

	logger.Info().
		Str("cache_file", cacheFile).
		Time("cached_at", cached.Metadata.CreatedAt).
		Int("total_files", index.TotalFiles()).
		Msg("Loaded file index from cache")

	return index, nil
}

// SaveInput holds the parameters for saving a file index to cache
type SaveInput struct {
	BaseDirs       []string
	ExcludePaths   []string
	Patterns       []fileindex.Pattern
	MaxDepth       int
	FollowSymlinks bool
	Index          *fileindex.FileIndex
	SampleSize     int // Number of files to sample for staleness detection
}

// Save persists a file index to cache
func (s *Store) Save(ctx context.Context, input SaveInput) error {
	logger := zerolog.Ctx(ctx)

	// Ensure cache directory exists
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	// Store expanded and normalized paths for consistent comparison on load
	expandedDirs := ExpandBaseDirs(input.BaseDirs)
	expandedExcludes := normalizeExcludePaths(input.ExcludePaths)
	entries := input.Index.GetAll()

	cached := CachedFileIndex{
		Metadata: Metadata{
			SchemaVersion:   SchemaVersion,
			CreatedAt:       time.Now(),
			BaseDirs:        expandedDirs,
			ExcludePaths:    expandedExcludes,
			PatternsHash:    computePatternsHash(input.Patterns),
			MaxDepth:        input.MaxDepth,
			FollowSymlinks:  input.FollowSymlinks,
			BaseDirModTimes: collectBaseDirModTimes(expandedDirs),
			FileSample:      selectFileSample(entries, input.SampleSize),
			TotalFileCount:  input.Index.TotalFiles(),
		},
		Entries: entries,
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache data: %w", err)
	}

	cacheFile := s.cacheFilePath(cacheKeyInput{
		baseDirs:       input.BaseDirs,
		excludePaths:   input.ExcludePaths,
		patterns:       input.Patterns,
		maxDepth:       input.MaxDepth,
		followSymlinks: input.FollowSymlinks,
	})

	// Write atomically: write to temp file, then rename
	tempFile := cacheFile + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o600); err != nil {
		return fmt.Errorf("write temp cache file: %w", err)
	}

	if err := os.Rename(tempFile, cacheFile); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tempFile)
		return fmt.Errorf("rename temp cache file: %w", err)
	}

	logger.Info().
		Str("cache_file", cacheFile).
		Int("total_files", input.Index.TotalFiles()).
		Msg("Saved file index to cache")

	return nil
}

// Clear removes all cache files in the cache directory.
// Subdirectories are skipped intentionally - this function only cleans
// files created by this cache package (fileindex-*.json).
func (s *Store) Clear() error {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(s.cacheDir, entry.Name())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove cache file %s: %w", path, err)
		}
	}

	return nil
}

// cacheFilePath returns the path to the cache file for the given configuration
func (s *Store) cacheFilePath(input cacheKeyInput) string {
	hash := computeCacheKey(input)
	return filepath.Join(s.cacheDir, cacheFilePrefix+hash+".json")
}

// cacheKeyInput holds parameters for computing the cache key
type cacheKeyInput struct {
	baseDirs       []string
	excludePaths   []string
	patterns       []fileindex.Pattern
	maxDepth       int
	followSymlinks bool
}

// computeCacheKey computes a hash based on the cache configuration
func computeCacheKey(input cacheKeyInput) string {
	h := sha256.New()

	// Include schema version
	fmt.Fprintf(h, "v%d\n", SchemaVersion)

	// Expand and sort base dirs for consistent hashing
	expandedDirs := ExpandBaseDirs(input.baseDirs)
	sort.Strings(expandedDirs)
	for _, dir := range expandedDirs {
		fmt.Fprintf(h, "dir:%s\n", dir)
	}

	// Normalize and sort exclude paths for consistent hashing; empty/whitespace
	// entries are dropped so they do not affect the cache key.
	normalizedExcludes := normalizeExcludePaths(input.excludePaths)
	sort.Strings(normalizedExcludes)
	for _, p := range normalizedExcludes {
		fmt.Fprintf(h, "exclude:%s\n", p)
	}

	// Include patterns hash
	fmt.Fprintf(h, "patterns:%s\n", computePatternsHash(input.patterns))

	// Include MaxDepth and FollowSymlinks
	fmt.Fprintf(h, "maxDepth:%d\n", input.maxDepth)
	fmt.Fprintf(h, "followSymlinks:%t\n", input.followSymlinks)

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// sortedCopy returns a sorted copy of a string slice
func sortedCopy(s []string) []string {
	c := make([]string, len(s))
	copy(c, s)
	sort.Strings(c)
	return c
}

// computePatternsHash computes a hash of the patterns configuration
func computePatternsHash(patterns []fileindex.Pattern) string {
	h := sha256.New()

	// Sort patterns by name for deterministic hash
	sortedPatterns := make([]fileindex.Pattern, len(patterns))
	copy(sortedPatterns, patterns)
	sort.Slice(sortedPatterns, func(i, j int) bool {
		return sortedPatterns[i].Name < sortedPatterns[j].Name
	})

	for _, p := range sortedPatterns {
		fmt.Fprintf(h, "name:%s\n", p.Name)
		fmt.Fprintf(h, "type:%s\n", p.Type)
		// Sort patterns within each pattern
		sortedPats := make([]string, len(p.Patterns))
		copy(sortedPats, p.Patterns)
		sort.Strings(sortedPats)
		for _, pat := range sortedPats {
			fmt.Fprintf(h, "pat:%s\n", pat)
		}
	}

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// slicesEqual compares two string slices for equality
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ExpandBaseDirs normalizes base directory paths by expanding ~, $HOME, %USERPROFILE%
func ExpandBaseDirs(baseDirs []string) []string {
	expanded := make([]string, 0, len(baseDirs))
	for _, dir := range baseDirs {
		expanded = append(expanded, expandPath(dir))
	}
	return expanded
}

// normalizeExcludePaths trims whitespace, drops empty entries, and fully expands
// and cleans each exclude path so that comparisons and cache keys are stable
// regardless of trailing slashes, leading spaces, or path separator style.
func normalizeExcludePaths(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		expanded := expandPath(trimmed)
		if expanded != "" && expanded != "." {
			result = append(result, filepath.Clean(filepath.FromSlash(expanded)))
		}
	}
	return result
}

// expandPath expands home directory variables and environment variables in a path.
// Handles ~, $HOME (Unix), and %USERPROFILE% (Windows).
func expandPath(path string) string {
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
	path = os.ExpandEnv(path)

	// Normalize path separators for the current OS
	return filepath.Clean(path)
}

// StalenessCheckInput holds parameters for checking cache staleness
type StalenessCheckInput struct {
	Metadata      Metadata
	TTL           time.Duration
	ValidateFiles bool
}

// StalenessResult represents the result of a staleness check
type StalenessResult struct {
	IsStale bool
	Reason  string // "ttl_expired", "base_dir_changed", "file_missing", "file_modified"
	Details string
}

// checkStaleness determines if the cached data is stale
func checkStaleness(input StalenessCheckInput) StalenessResult {
	// 1. TTL check (fastest - no I/O)
	if input.TTL > 0 && time.Since(input.Metadata.CreatedAt) > input.TTL {
		return StalenessResult{
			IsStale: true,
			Reason:  "ttl_expired",
			Details: fmt.Sprintf("cache age %s exceeds TTL %s", time.Since(input.Metadata.CreatedAt).Round(time.Second), input.TTL),
		}
	}

	// 2. Base directory mtime check (one stat per base dir)
	for dir, cachedMtime := range input.Metadata.BaseDirModTimes {
		info, err := os.Stat(dir)
		if err != nil {
			return StalenessResult{
				IsStale: true,
				Reason:  "base_dir_changed",
				Details: fmt.Sprintf("cannot stat base dir %s: %v", dir, err),
			}
		}
		if info.ModTime().UnixNano() != cachedMtime {
			return StalenessResult{
				IsStale: true,
				Reason:  "base_dir_changed",
				Details: fmt.Sprintf("base dir %s mtime changed", dir),
			}
		}
	}

	// 3. File sample validation (if enabled)
	if input.ValidateFiles {
		for _, sample := range input.Metadata.FileSample {
			info, err := os.Stat(sample.Path)
			if os.IsNotExist(err) {
				return StalenessResult{
					IsStale: true,
					Reason:  "file_missing",
					Details: fmt.Sprintf("sampled file %s no longer exists", sample.Path),
				}
			}
			if err != nil {
				// Other errors (permissions, etc.) - treat as stale to be safe
				return StalenessResult{
					IsStale: true,
					Reason:  "file_missing",
					Details: fmt.Sprintf("cannot stat sampled file %s: %v", sample.Path, err),
				}
			}
			if info.ModTime().UnixNano() != sample.ModTime || info.Size() != sample.Size {
				return StalenessResult{
					IsStale: true,
					Reason:  "file_modified",
					Details: fmt.Sprintf("sampled file %s was modified", sample.Path),
				}
			}
		}
	}

	return StalenessResult{IsStale: false}
}

// collectBaseDirModTimes stats each base directory and returns their modification times
func collectBaseDirModTimes(baseDirs []string) map[string]int64 {
	modTimes := make(map[string]int64, len(baseDirs))
	for _, dir := range baseDirs {
		info, err := os.Stat(dir)
		if err != nil {
			continue // Skip directories that can't be stated
		}
		modTimes[dir] = info.ModTime().UnixNano()
	}
	return modTimes
}

// selectFileSample selects a representative sample of files from the index entries
// The sample is evenly distributed across all files for better coverage
func selectFileSample(entries map[string][]string, sampleSize int) []FileSampleEntry {
	if sampleSize <= 0 {
		return nil
	}

	// Flatten all paths
	var allPaths []string
	for _, paths := range entries {
		allPaths = append(allPaths, paths...)
	}

	if len(allPaths) == 0 {
		return nil
	}

	// Sort for deterministic selection
	sort.Strings(allPaths)

	// Select evenly distributed sample
	var selectedPaths []string
	if len(allPaths) <= sampleSize {
		selectedPaths = allPaths
	} else {
		// Select evenly spaced indices
		step := float64(len(allPaths)) / float64(sampleSize)
		for i := 0; i < sampleSize; i++ {
			idx := int(float64(i) * step)
			selectedPaths = append(selectedPaths, allPaths[idx])
		}
	}

	// Stat each file to get ModTime and Size
	sample := make([]FileSampleEntry, 0, len(selectedPaths))
	for _, path := range selectedPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue // Skip files that can't be stated
		}
		sample = append(sample, FileSampleEntry{
			Path:    path,
			ModTime: info.ModTime().UnixNano(),
			Size:    info.Size(),
		})
	}

	return sample
}
