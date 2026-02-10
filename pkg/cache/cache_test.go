// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCacheDir(t *testing.T) {
	t.Parallel()

	dir, err := GetCacheDir()
	require.NoError(t, err)
	assert.NotEmpty(t, dir)

	switch runtime.GOOS {
	case "darwin":
		assert.Contains(t, dir, "Library/Caches/bagel")
	case "linux":
		assert.Contains(t, dir, "bagel")
	case "windows":
		assert.Contains(t, dir, "bagel")
		assert.Contains(t, dir, "cache")
	}
}

func TestNewStore(t *testing.T) {
	t.Parallel()

	store, err := NewStore()
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.NotEmpty(t, store.cacheDir)
}

func TestStore_SaveAndLoad(t *testing.T) {
	t.Parallel()

	// Create temp directory for test
	tempDir := t.TempDir()

	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	// Use fake paths that don't exist to avoid staleness checks based on real filesystem
	// (real paths like /tmp can have mtime changes from parallel tests)
	baseDirs := []string{"/nonexistent/home/user", "/nonexistent/data"}
	patterns := []fileindex.Pattern{
		{
			Name:     "ssh_config",
			Patterns: []string{".ssh/config", ".ssh/config.d/*"},
			Type:     fileindex.PatternTypeGlob,
		},
		{
			Name:     "git_config",
			Patterns: []string{".gitconfig"},
			Type:     fileindex.PatternTypeExact,
		},
	}

	// Create a file index
	index := fileindex.NewFileIndex()
	index.Add("ssh_config", "/nonexistent/home/user/.ssh/config")
	index.Add("ssh_config", "/nonexistent/home/user/.ssh/config.d/work")
	index.Add("git_config", "/nonexistent/home/user/.gitconfig")

	// Save to cache
	saveInput := SaveInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       10,
		FollowSymlinks: true,
		Index:          index,
	}
	err := store.Save(ctx, saveInput)
	require.NoError(t, err)

	// Verify cache file exists
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.True(t, strings.HasPrefix(entries[0].Name(), cacheFilePrefix))

	// Load from cache
	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       10,
		FollowSymlinks: true,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	// Verify loaded data matches original
	assert.Equal(t, index.TotalFiles(), loaded.TotalFiles())
	assert.ElementsMatch(t, index.Get("ssh_config"), loaded.Get("ssh_config"))
	assert.ElementsMatch(t, index.Get("git_config"), loaded.Get("git_config"))
}

func TestStore_Load_CacheMiss(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	// Load from empty cache
	loadInput := LoadInput{
		BaseDirs:       []string{"/home/user"},
		Patterns:       []fileindex.Pattern{{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob}},
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestStore_Load_InvalidJSON(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Write invalid JSON to cache file
	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	require.NoError(t, os.MkdirAll(tempDir, 0o700))
	require.NoError(t, os.WriteFile(cacheFile, []byte("invalid json"), 0o600))

	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err) // Should not error, just return nil
	assert.Nil(t, loaded)
}

func TestStore_Load_SchemaVersionMismatch(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Write cache with wrong schema version
	cached := CachedFileIndex{
		Metadata: Metadata{
			SchemaVersion:  SchemaVersion + 1, // Future version
			CreatedAt:      time.Now(),
			BaseDirs:       baseDirs,
			PatternsHash:   computePatternsHash(patterns),
			MaxDepth:       5,
			FollowSymlinks: false,
		},
		Entries: map[string][]string{"test": {"/home/user/file.txt"}},
	}

	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	require.NoError(t, os.MkdirAll(tempDir, 0o700))
	data, _ := json.Marshal(cached)
	require.NoError(t, os.WriteFile(cacheFile, data, 0o600))

	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded) // Should be treated as cache miss
}

func TestStore_Load_PatternsHashMismatch(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Write cache with wrong patterns hash
	cached := CachedFileIndex{
		Metadata: Metadata{
			SchemaVersion:  SchemaVersion,
			CreatedAt:      time.Now(),
			BaseDirs:       baseDirs,
			PatternsHash:   "wronghash12345678",
			MaxDepth:       5,
			FollowSymlinks: false,
		},
		Entries: map[string][]string{"test": {"/home/user/file.txt"}},
	}

	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	require.NoError(t, os.MkdirAll(tempDir, 0o700))
	data, _ := json.Marshal(cached)
	require.NoError(t, os.WriteFile(cacheFile, data, 0o600))

	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded)
}

func TestStore_Load_BaseDirsMismatch(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Save with one set of base dirs
	index := fileindex.NewFileIndex()
	index.Add("test", "/home/user/file.txt")

	err := store.Save(ctx, SaveInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	})
	require.NoError(t, err)

	// Try to load with different base dirs
	loadInput := LoadInput{
		BaseDirs:       []string{"/home/other"}, // Different!
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded) // Different hash means different file, so no cache
}

func TestStore_Clear(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	// Create some cache files
	patterns1 := []fileindex.Pattern{
		{Name: "test1", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}
	patterns2 := []fileindex.Pattern{
		{Name: "test2", Patterns: []string{"*.md"}, Type: fileindex.PatternTypeGlob},
	}

	index := fileindex.NewFileIndex()
	index.Add("test1", "/home/user/file.txt")

	require.NoError(t, store.Save(ctx, SaveInput{
		BaseDirs:       []string{"/home/user"},
		Patterns:       patterns1,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	}))

	require.NoError(t, store.Save(ctx, SaveInput{
		BaseDirs:       []string{"/home/user"},
		Patterns:       patterns2,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	}))

	// Verify files exist
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Clear cache
	require.NoError(t, store.Clear())

	// Verify files are gone
	entries, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestStore_Clear_NonexistentDir(t *testing.T) {
	t.Parallel()

	store := &Store{cacheDir: "/nonexistent/path/that/does/not/exist"}

	// Should not error when directory doesn't exist
	err := store.Clear()
	assert.NoError(t, err)
}

func TestComputePatternsHash_Deterministic(t *testing.T) {
	t.Parallel()

	patterns := []fileindex.Pattern{
		{Name: "b", Patterns: []string{"*.md", "*.txt"}, Type: fileindex.PatternTypeGlob},
		{Name: "a", Patterns: []string{"config"}, Type: fileindex.PatternTypeExact},
	}

	hash1 := computePatternsHash(patterns)
	hash2 := computePatternsHash(patterns)

	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 16)
}

func TestComputePatternsHash_OrderIndependent(t *testing.T) {
	t.Parallel()

	patterns1 := []fileindex.Pattern{
		{Name: "a", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
		{Name: "b", Patterns: []string{"*.md"}, Type: fileindex.PatternTypeGlob},
	}
	patterns2 := []fileindex.Pattern{
		{Name: "b", Patterns: []string{"*.md"}, Type: fileindex.PatternTypeGlob},
		{Name: "a", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	assert.Equal(t, computePatternsHash(patterns1), computePatternsHash(patterns2))
}

func TestComputeCacheKey_Deterministic(t *testing.T) {
	t.Parallel()

	input := cacheKeyInput{
		baseDirs:       []string{"/home/user", "/tmp"},
		patterns:       []fileindex.Pattern{{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob}},
		maxDepth:       10,
		followSymlinks: true,
	}

	key1 := computeCacheKey(input)
	key2 := computeCacheKey(input)

	assert.Equal(t, key1, key2)
	assert.Len(t, key1, 16)
}

func TestComputeCacheKey_DifferentForDifferentConfigs(t *testing.T) {
	t.Parallel()

	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	key1 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/user"}, patterns: patterns, maxDepth: 5, followSymlinks: false})
	key2 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/other"}, patterns: patterns, maxDepth: 5, followSymlinks: false})

	assert.NotEqual(t, key1, key2)
}

func TestComputeCacheKey_DifferentForMaxDepth(t *testing.T) {
	t.Parallel()

	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	key1 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/user"}, patterns: patterns, maxDepth: 5, followSymlinks: false})
	key2 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/user"}, patterns: patterns, maxDepth: 10, followSymlinks: false})

	assert.NotEqual(t, key1, key2)
}

func TestComputeCacheKey_DifferentForFollowSymlinks(t *testing.T) {
	t.Parallel()

	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	key1 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/user"}, patterns: patterns, maxDepth: 5, followSymlinks: false})
	key2 := computeCacheKey(cacheKeyInput{baseDirs: []string{"/home/user"}, patterns: patterns, maxDepth: 5, followSymlinks: true})

	assert.NotEqual(t, key1, key2)
}

func TestSlicesEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "c"},
			expected: true,
		},
		{
			name:     "different length",
			a:        []string{"a", "b"},
			b:        []string{"a", "b", "c"},
			expected: false,
		},
		{
			name:     "different content",
			a:        []string{"a", "b", "c"},
			b:        []string{"a", "b", "d"},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, slicesEqual(tt.a, tt.b))
		})
	}
}

func TestStore_Save_CreatesDirectory(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	nestedDir := filepath.Join(tempDir, "nested", "cache", "dir")

	store := &Store{cacheDir: nestedDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	index := fileindex.NewFileIndex()
	index.Add("test", "/home/user/file.txt")

	err := store.Save(ctx, SaveInput{
		BaseDirs:       []string{"/home/user"},
		Patterns:       []fileindex.Pattern{{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob}},
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	})
	require.NoError(t, err)

	// Verify directory was created
	info, err := os.Stat(nestedDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestExpandBaseDirs(t *testing.T) {
	t.Parallel()

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "tilde expansion",
			input:    []string{"~/documents", "~/projects"},
			expected: []string{filepath.Join(homeDir, "documents"), filepath.Join(homeDir, "projects")},
		},
		{
			name:     "absolute paths unchanged",
			input:    []string{"/home/user", "/tmp"},
			expected: []string{filepath.Clean("/home/user"), filepath.Clean("/tmp")},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "HOME variable expansion",
			input:    []string{"$HOME/documents"},
			expected: []string{filepath.Join(homeDir, "documents")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ExpandBaseDirs(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStore_Load_MaxDepthMismatch(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Save with MaxDepth = 5
	index := fileindex.NewFileIndex()
	index.Add("test", "/home/user/file.txt")

	err := store.Save(ctx, SaveInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	})
	require.NoError(t, err)

	// Try to load with different MaxDepth
	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       10, // Different!
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded) // Different hash means different file, so no cache
}

func TestStore_Load_FollowSymlinksMismatch(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Save with FollowSymlinks = false
	index := fileindex.NewFileIndex()
	index.Add("test", "/home/user/file.txt")

	err := store.Save(ctx, SaveInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	})
	require.NoError(t, err)

	// Try to load with different FollowSymlinks
	loadInput := LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: true, // Different!
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	assert.Nil(t, loaded) // Different hash means different file, so no cache
}

func TestStore_CacheHit_WithTildeExpansion(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Save with tilde notation
	index := fileindex.NewFileIndex()
	index.Add("test", filepath.Join(homeDir, "file.txt"))

	err = store.Save(ctx, SaveInput{
		BaseDirs:       []string{"~"},
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
	})
	require.NoError(t, err)

	// Load with expanded path - should hit cache because both are expanded
	loadInput := LoadInput{
		BaseDirs:       []string{homeDir},
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
	}
	loaded, err := store.Load(ctx, loadInput)
	require.NoError(t, err)
	require.NotNil(t, loaded, "Should hit cache when using equivalent expanded path")
	assert.Equal(t, index.TotalFiles(), loaded.TotalFiles())
}

func TestCheckStaleness_TTLExpired(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt: time.Now().Add(-1 * time.Hour), // Created 1 hour ago
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           30 * time.Minute, // TTL is 30 minutes
		ValidateFiles: false,
	})

	assert.True(t, result.IsStale)
	assert.Equal(t, "ttl_expired", result.Reason)
	assert.Contains(t, result.Details, "exceeds TTL")
}

func TestCheckStaleness_TTLNotExpired(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt: time.Now().Add(-10 * time.Minute), // Created 10 minutes ago
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           30 * time.Minute, // TTL is 30 minutes
		ValidateFiles: false,
	})

	assert.False(t, result.IsStale)
}

func TestCheckStaleness_TTLZeroDisablesCheck(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt: time.Now().Add(-24 * time.Hour), // Created 24 hours ago
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           0, // TTL disabled
		ValidateFiles: false,
	})

	assert.False(t, result.IsStale)
}

func TestCheckStaleness_BaseDirChanged(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Get initial mtime
	info, err := os.Stat(tempDir)
	require.NoError(t, err)
	initialMtime := info.ModTime().UnixNano()

	// Modify directory by creating a file
	testFile := filepath.Join(tempDir, "newfile.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("content"), 0o600))

	// Get new mtime (should be different)
	info, err = os.Stat(tempDir)
	require.NoError(t, err)

	// Only run assertion if mtime actually changed (some filesystems may not update dir mtime)
	if info.ModTime().UnixNano() != initialMtime {
		metadata := Metadata{
			CreatedAt:       time.Now(),
			BaseDirModTimes: map[string]int64{tempDir: initialMtime}, // Old mtime
		}

		result := checkStaleness(StalenessCheckInput{
			Metadata:      metadata,
			TTL:           0,
			ValidateFiles: false,
		})

		assert.True(t, result.IsStale)
		assert.Equal(t, "base_dir_changed", result.Reason)
	}
}

func TestCheckStaleness_BaseDirMissing(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt:       time.Now(),
		BaseDirModTimes: map[string]int64{"/nonexistent/path/that/does/not/exist": 12345},
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           0,
		ValidateFiles: false,
	})

	assert.True(t, result.IsStale)
	assert.Equal(t, "base_dir_changed", result.Reason)
	assert.Contains(t, result.Details, "cannot stat")
}

func TestCheckStaleness_FileMissing(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt: time.Now(),
		FileSample: []FileSampleEntry{
			{Path: "/nonexistent/file.txt", ModTime: 12345, Size: 100},
		},
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           0,
		ValidateFiles: true,
	})

	assert.True(t, result.IsStale)
	assert.Equal(t, "file_missing", result.Reason)
	assert.Contains(t, result.Details, "no longer exists")
}

func TestCheckStaleness_FileModified(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")

	// Create file
	require.NoError(t, os.WriteFile(testFile, []byte("original"), 0o600))

	info, err := os.Stat(testFile)
	require.NoError(t, err)
	originalMtime := info.ModTime().UnixNano()
	originalSize := info.Size()

	// Modify file
	time.Sleep(10 * time.Millisecond) // Ensure mtime changes
	require.NoError(t, os.WriteFile(testFile, []byte("modified content"), 0o600))

	metadata := Metadata{
		CreatedAt: time.Now(),
		FileSample: []FileSampleEntry{
			{Path: testFile, ModTime: originalMtime, Size: originalSize},
		},
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           0,
		ValidateFiles: true,
	})

	assert.True(t, result.IsStale)
	assert.Equal(t, "file_modified", result.Reason)
	assert.Contains(t, result.Details, "was modified")
}

func TestCheckStaleness_FileNotValidatedWhenDisabled(t *testing.T) {
	t.Parallel()

	metadata := Metadata{
		CreatedAt: time.Now(),
		FileSample: []FileSampleEntry{
			{Path: "/nonexistent/file.txt", ModTime: 12345, Size: 100},
		},
	}

	result := checkStaleness(StalenessCheckInput{
		Metadata:      metadata,
		TTL:           0,
		ValidateFiles: false, // Disabled
	})

	assert.False(t, result.IsStale) // Should not check files
}

func TestCollectBaseDirModTimes(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	modTimes := collectBaseDirModTimes([]string{tempDir, "/nonexistent/path"})

	// Should have entry for tempDir
	assert.Contains(t, modTimes, tempDir)
	assert.Positive(t, modTimes[tempDir])

	// Should NOT have entry for nonexistent path
	assert.NotContains(t, modTimes, "/nonexistent/path")
}

func TestSelectFileSample_EmptyEntries(t *testing.T) {
	t.Parallel()

	sample := selectFileSample(map[string][]string{}, 50)
	assert.Empty(t, sample)
}

func TestSelectFileSample_ZeroSampleSize(t *testing.T) {
	t.Parallel()

	entries := map[string][]string{
		"test": {"/path/to/file.txt"},
	}
	sample := selectFileSample(entries, 0)
	assert.Nil(t, sample)
}

func TestSelectFileSample_FewerFilesThanSampleSize(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create test files
	file1 := filepath.Join(tempDir, "file1.txt")
	file2 := filepath.Join(tempDir, "file2.txt")
	require.NoError(t, os.WriteFile(file1, []byte("content1"), 0o600))
	require.NoError(t, os.WriteFile(file2, []byte("content2"), 0o600))

	entries := map[string][]string{
		"test": {file1, file2},
	}

	sample := selectFileSample(entries, 50) // Sample size larger than available files

	assert.Len(t, sample, 2) // Should include all files
}

func TestSelectFileSample_EvenDistribution(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Create 10 test files
	var files []string
	for i := 0; i < 10; i++ {
		f := filepath.Join(tempDir, fmt.Sprintf("file%02d.txt", i))
		require.NoError(t, os.WriteFile(f, []byte(fmt.Sprintf("content%d", i)), 0o600))
		files = append(files, f)
	}

	entries := map[string][]string{
		"test": files,
	}

	sample := selectFileSample(entries, 3) // Sample 3 out of 10

	assert.Len(t, sample, 3)
	// Verify samples have valid data
	for _, s := range sample {
		assert.NotEmpty(t, s.Path)
		assert.Positive(t, s.ModTime)
		assert.Positive(t, s.Size)
	}
}

func TestSelectFileSample_SkipsNonexistentFiles(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	existingFile := filepath.Join(tempDir, "existing.txt")
	require.NoError(t, os.WriteFile(existingFile, []byte("content"), 0o600))

	entries := map[string][]string{
		"test": {existingFile, "/nonexistent/file.txt"},
	}

	sample := selectFileSample(entries, 10)

	// Should only include the existing file
	assert.Len(t, sample, 1)
	assert.Equal(t, existingFile, sample[0].Path)
}

func TestStore_SaveAndLoad_WithStalenessFields(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Use separate directories for cache and test files to avoid mtime changes
	cacheDir := filepath.Join(tempDir, "cache")
	testDataDir := filepath.Join(tempDir, "data")
	require.NoError(t, os.MkdirAll(cacheDir, 0o700))
	require.NoError(t, os.MkdirAll(testDataDir, 0o700))

	store := &Store{cacheDir: cacheDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	// Create real test files for sampling
	testFile := filepath.Join(testDataDir, "testfile.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test content"), 0o600))

	baseDirs := []string{testDataDir}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("test", testFile)

	// Save with sample size
	err := store.Save(ctx, SaveInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		Index:          index,
		SampleSize:     10,
	})
	require.NoError(t, err)

	// Verify cache file has staleness fields
	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	data, err := os.ReadFile(cacheFile)
	require.NoError(t, err)

	var cached CachedFileIndex
	require.NoError(t, json.Unmarshal(data, &cached))

	// Verify staleness fields are populated
	assert.NotEmpty(t, cached.Metadata.BaseDirModTimes)
	assert.Contains(t, cached.Metadata.BaseDirModTimes, testDataDir)
	assert.NotEmpty(t, cached.Metadata.FileSample)
	assert.Equal(t, 1, cached.Metadata.TotalFileCount)

	// Load and verify it works
	loaded, err := store.Load(ctx, LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		TTL:            30 * time.Minute,
		ValidateFiles:  true,
	})
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, 1, loaded.TotalFiles())
}

func TestStore_Load_StaleByTTL(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := &Store{cacheDir: tempDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	baseDirs := []string{"/home/user"}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Write cache with old timestamp
	cached := CachedFileIndex{
		Metadata: Metadata{
			SchemaVersion:   SchemaVersion,
			CreatedAt:       time.Now().Add(-2 * time.Hour), // 2 hours ago
			BaseDirs:        baseDirs,
			PatternsHash:    computePatternsHash(patterns),
			MaxDepth:        5,
			FollowSymlinks:  false,
			BaseDirModTimes: map[string]int64{},
			FileSample:      []FileSampleEntry{},
			TotalFileCount:  1,
		},
		Entries: map[string][]string{"test": {"/home/user/file.txt"}},
	}

	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	require.NoError(t, os.MkdirAll(tempDir, 0o700))
	data, _ := json.Marshal(cached)
	require.NoError(t, os.WriteFile(cacheFile, data, 0o600))

	// Load with 1 hour TTL - should be stale
	loaded, err := store.Load(ctx, LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		TTL:            1 * time.Hour,
		ValidateFiles:  false,
	})
	require.NoError(t, err)
	assert.Nil(t, loaded, "Should return nil for stale cache")
}

func TestStore_Load_StaleByFileModification(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()

	// Use separate directories for cache and test data
	cacheDir := filepath.Join(tempDir, "cache")
	testDataDir := filepath.Join(tempDir, "data")
	require.NoError(t, os.MkdirAll(cacheDir, 0o700))
	require.NoError(t, os.MkdirAll(testDataDir, 0o700))

	store := &Store{cacheDir: cacheDir}

	ctx := zerolog.New(os.Stderr).WithContext(context.Background())

	// Create a test file
	testFile := filepath.Join(testDataDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("original"), 0o600))

	info, err := os.Stat(testFile)
	require.NoError(t, err)

	baseDirs := []string{testDataDir}
	patterns := []fileindex.Pattern{
		{Name: "test", Patterns: []string{"*.txt"}, Type: fileindex.PatternTypeGlob},
	}

	// Write cache with current file state
	cached := CachedFileIndex{
		Metadata: Metadata{
			SchemaVersion:   SchemaVersion,
			CreatedAt:       time.Now(),
			BaseDirs:        baseDirs,
			PatternsHash:    computePatternsHash(patterns),
			MaxDepth:        5,
			FollowSymlinks:  false,
			BaseDirModTimes: collectBaseDirModTimes(baseDirs),
			FileSample: []FileSampleEntry{
				{Path: testFile, ModTime: info.ModTime().UnixNano(), Size: info.Size()},
			},
			TotalFileCount: 1,
		},
		Entries: map[string][]string{"test": {testFile}},
	}

	cacheFile := store.cacheFilePath(cacheKeyInput{
		baseDirs:       baseDirs,
		patterns:       patterns,
		maxDepth:       5,
		followSymlinks: false,
	})
	data, _ := json.Marshal(cached)
	require.NoError(t, os.WriteFile(cacheFile, data, 0o600))

	// Modify the file
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, os.WriteFile(testFile, []byte("modified content that is longer"), 0o600))

	// Load with file validation - should be stale due to file modification
	loaded, err := store.Load(ctx, LoadInput{
		BaseDirs:       baseDirs,
		Patterns:       patterns,
		MaxDepth:       5,
		FollowSymlinks: false,
		TTL:            0,
		ValidateFiles:  true,
	})
	require.NoError(t, err)
	assert.Nil(t, loaded, "Should return nil for stale cache due to file modification")
}
