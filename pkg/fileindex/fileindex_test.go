// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package fileindex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileIndex(t *testing.T) {
	index := NewFileIndex()
	assert.NotNil(t, index)
	assert.NotNil(t, index.entries)
	assert.Equal(t, 0, index.TotalFiles())
}

func TestFileIndex_AddAndGet(t *testing.T) {
	index := NewFileIndex()

	// Add some files
	index.Add("ssh_config", "/home/user/.ssh/config")
	index.Add("ssh_config", "/home/user/.ssh/config.d/test")
	index.Add("gitconfig", "/home/user/.gitconfig")

	// Test Get
	sshFiles := index.Get("ssh_config")
	assert.Len(t, sshFiles, 2)
	assert.Contains(t, sshFiles, "/home/user/.ssh/config")
	assert.Contains(t, sshFiles, "/home/user/.ssh/config.d/test")

	gitFiles := index.Get("gitconfig")
	assert.Len(t, gitFiles, 1)
	assert.Contains(t, gitFiles, "/home/user/.gitconfig")

	// Test non-existent pattern
	nonExistent := index.Get("does_not_exist")
	assert.Empty(t, nonExistent)
}

func TestFileIndex_GetAll(t *testing.T) {
	index := NewFileIndex()

	index.Add("ssh_config", "/home/user/.ssh/config")
	index.Add("gitconfig", "/home/user/.gitconfig")

	all := index.GetAll()
	assert.Len(t, all, 2)
	assert.Contains(t, all, "ssh_config")
	assert.Contains(t, all, "gitconfig")

	// Verify it's a deep copy
	all["ssh_config"] = append(all["ssh_config"], "/modified")
	originalSSH := index.Get("ssh_config")
	assert.Len(t, originalSSH, 1)
}

func TestFileIndex_TotalFiles(t *testing.T) {
	index := NewFileIndex()
	assert.Equal(t, 0, index.TotalFiles())

	index.Add("pattern1", "/file1")
	assert.Equal(t, 1, index.TotalFiles())

	index.Add("pattern1", "/file2")
	assert.Equal(t, 2, index.TotalFiles())

	index.Add("pattern2", "/file3")
	assert.Equal(t, 3, index.TotalFiles())
}

func TestBuildIndex_WithRealFiles(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()

	// Create test files
	testFiles := map[string]string{
		".gitconfig":                 "git config content",
		".ssh/config":                "ssh config content",
		".ssh/id_rsa":                "private key",
		".ssh/id_rsa.pub":            "public key",
		".config/git/config":         "git config in XDG",
		"subdir/.env":                "env vars",
		"deep/nested/dir/.npmrc":     "npm config",
		"regular_file.txt":           "regular file",
		".hidden_but_not_matched":    "hidden file",
		"should_not_match/file.conf": "random config",
		"repo/.git/config":           "repo git config",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tmpDir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0644))
	}

	// Build index
	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig", ".config/git/config", ".git/config"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "ssh_config",
			Patterns: []string{".ssh/config"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "ssh_keys",
			Patterns: []string{".ssh/id_*"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "env_files",
			Patterns: []string{".env"},
			Type:     PatternTypeExact,
		},
		{
			Name:     "npmrc",
			Patterns: []string{".npmrc"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, index)

	// Verify gitconfig matches
	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 3)
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir, ".gitconfig"))
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir, ".config/git/config"))
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir, "repo/.git/config"))

	// Verify ssh_config matches
	sshConfigs := index.Get("ssh_config")
	assert.Len(t, sshConfigs, 1)
	assert.Contains(t, sshConfigs, filepath.Join(tmpDir, ".ssh/config"))

	// Verify ssh_keys matches
	sshKeys := index.Get("ssh_keys")
	assert.Len(t, sshKeys, 2)
	assert.Contains(t, sshKeys, filepath.Join(tmpDir, ".ssh/id_rsa"))
	assert.Contains(t, sshKeys, filepath.Join(tmpDir, ".ssh/id_rsa.pub"))

	// Verify env_files matches
	envFiles := index.Get("env_files")
	assert.Len(t, envFiles, 1)
	assert.Contains(t, envFiles, filepath.Join(tmpDir, "subdir/.env"))

	// Verify npmrc matches
	npmrcs := index.Get("npmrc")
	assert.Len(t, npmrcs, 1)
	assert.Contains(t, npmrcs, filepath.Join(tmpDir, "deep/nested/dir/.npmrc"))

	// Verify total file count
	totalFiles := index.TotalFiles()
	assert.Equal(t, 8, totalFiles)
}

func TestBuildIndex_WithMaxDepth(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested structure
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "level1/level2/level3"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("root"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "level1/.env"), []byte("l1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "level1/level2/.env"), []byte("l2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "level1/level2/level3/.env"), []byte("l3"), 0644))

	patterns := []Pattern{
		{
			Name:     "env_files",
			Patterns: []string{".env"},
			Type:     PatternTypeExact,
		},
	}

	// Test with MaxDepth = 2
	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       2,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	envFiles := index.Get("env_files")
	// Should find: root, level1, level2 (but not level3 due to max depth)
	assert.Len(t, envFiles, 3)
}

func TestBuildIndex_WithSymlinks(t *testing.T) {
	tmpDir := t.TempDir()

	// Create actual directory with file
	actualDir := filepath.Join(tmpDir, "actual")
	require.NoError(t, os.MkdirAll(actualDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(actualDir, ".gitconfig"), []byte("content"), 0644))

	// Create symlink
	symlinkPath := filepath.Join(tmpDir, "linked")
	err := os.Symlink(actualDir, symlinkPath)
	if err != nil {
		t.Skip("Symlinks not supported on this platform")
	}

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig"},
			Type:     PatternTypeExact,
		},
	}

	// Test without following symlinks
	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	gitconfigs := index.Get("gitconfig")
	// Should only find the actual file, not through symlink
	assert.Len(t, gitconfigs, 1)

	// Test with following symlinks
	input.FollowSymlinks = true
	index, err = BuildIndex(ctx, input)
	require.NoError(t, err)

	gitconfigs = index.Get("gitconfig")
	// Should find both actual and symlinked version (resolved to same file)
	assert.GreaterOrEqual(t, len(gitconfigs), 1)
}

func TestBuildIndex_NonExistentDirectory(t *testing.T) {
	patterns := []Pattern{
		{
			Name:     "test",
			Patterns: []string{"*"},
			Type:     PatternTypeGlob,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{"/nonexistent/directory/that/does/not/exist"},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)

	// Should succeed but with no files
	require.NoError(t, err)
	assert.Equal(t, 0, index.TotalFiles())
}

func TestBuildIndex_EnvironmentVariableExpansion(t *testing.T) {
	tmpDir := t.TempDir()

	// Set a test environment variable
	t.Setenv("TEST_BASE_DIR", tmpDir)

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, ".gitconfig"), []byte("content"), 0644))

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{"$TEST_BASE_DIR"},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 1)
}

func TestPatternMatching_GlobPatterns(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		".ssh/id_rsa",
		".ssh/id_ed25519",
		".ssh/id_ecdsa",
		".ssh/config",
		".ssh/known_hosts",
	}

	for _, file := range testFiles {
		fullPath := filepath.Join(tmpDir, file)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755))
		require.NoError(t, os.WriteFile(fullPath, []byte("content"), 0644))
	}

	patterns := []Pattern{
		{
			Name:     "ssh_keys",
			Patterns: []string{"id_*"},
			Type:     PatternTypeGlob,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	sshKeys := index.Get("ssh_keys")
	assert.Len(t, sshKeys, 3) // Should match id_rsa, id_ed25519, id_ecdsa
}

func TestPatternMatching_ExactMatch(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		".gitconfig",
		".gitconfig_backup",
		"gitconfig",
	}

	for _, file := range testFiles {
		require.NoError(t, os.WriteFile(filepath.Join(tmpDir, file), []byte("content"), 0644))
	}

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 1) // Should only match exact .gitconfig
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir, ".gitconfig"))
}

func TestFileIndex_Concurrency(t *testing.T) {
	index := NewFileIndex()

	// Test concurrent writes
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				index.Add("pattern", filepath.Join("/path", "file", string(rune(id)), string(rune(j))))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no race conditions occurred
	assert.Equal(t, 1000, index.TotalFiles())
}

func TestBuildIndex_Concurrent_Basic(t *testing.T) {
	t.Parallel()

	// Create a temporary directory structure with many files
	tmpDir := t.TempDir()

	// Create test files across multiple directories
	testFiles := map[string]string{
		".gitconfig":                     "git config content",
		".ssh/config":                    "ssh config content",
		".ssh/id_rsa":                    "private key",
		".ssh/id_rsa.pub":                "public key",
		".config/git/config":             "git config in XDG",
		"subdir/.env":                    "env vars",
		"deep/nested/dir/.npmrc":         "npm config",
		"regular_file.txt":               "regular file",
		".hidden_but_not_matched":        "hidden file",
		"should_not_match/file.conf":     "random config",
		"repo/.git/config":               "repo git config",
		"dir1/.env":                      "env1",
		"dir2/.env":                      "env2",
		"dir3/subdir/.env":               "env3",
		"projects/proj1/.gitconfig":      "proj1 config",
		"projects/proj2/.ssh/config":     "proj2 ssh",
		"projects/proj3/deep/dir/.npmrc": "proj3 npm",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tmpDir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0644))
	}

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig", ".config/git/config", ".git/config"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "ssh_config",
			Patterns: []string{".ssh/config"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "ssh_keys",
			Patterns: []string{".ssh/id_*"},
			Type:     PatternTypeGlob,
		},
		{
			Name:     "env_files",
			Patterns: []string{".env"},
			Type:     PatternTypeExact,
		},
		{
			Name:     "npmrc",
			Patterns: []string{".npmrc"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, index)

	// Verify gitconfig matches (3 base + 1 proj)
	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 4)

	// Verify ssh_config matches (1 base + 1 proj)
	sshConfigs := index.Get("ssh_config")
	assert.Len(t, sshConfigs, 2)

	// Verify ssh_keys matches
	sshKeys := index.Get("ssh_keys")
	assert.Len(t, sshKeys, 2)

	// Verify env_files matches (4 total)
	envFiles := index.Get("env_files")
	assert.Len(t, envFiles, 4)

	// Verify npmrc matches (2 total)
	npmrcs := index.Get("npmrc")
	assert.Len(t, npmrcs, 2)
}

func TestBuildIndex_Concurrent_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a directory with many files to ensure we have time to cancel
	tmpDir := t.TempDir()

	// Create many nested directories with files
	for i := 0; i < 50; i++ {
		dirPath := filepath.Join(tmpDir, fmt.Sprintf("dir%c%d", 'a'+i%26, i/26))
		require.NoError(t, os.MkdirAll(dirPath, 0755))
		for j := 0; j < 20; j++ {
			filePath := filepath.Join(dirPath, fmt.Sprintf("file%02d.txt", j))
			require.NoError(t, os.WriteFile(filePath, []byte("content"), 0644))
		}
	}

	patterns := []Pattern{
		{
			Name:     "all_txt",
			Patterns: []string{"*.txt"},
			Type:     PatternTypeGlob,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	// Create a context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start index building in a goroutine
	done := make(chan struct{})
	var buildErr error
	var index *FileIndex
	go func() {
		index, buildErr = BuildIndex(ctx, input)
		close(done)
	}()

	// Cancel context immediately
	cancel()

	// Wait for completion
	<-done

	// The function should complete (either with partial results or error)
	// Due to concurrent nature, it may complete before cancellation is processed
	// What matters is that it doesn't hang and respects cancellation
	if buildErr != nil {
		require.ErrorIs(t, buildErr, context.Canceled)
	}
	// Index is always returned (possibly partial)
	assert.NotNil(t, index)
}

func TestBuildIndex_ParallelTraversal(t *testing.T) {
	t.Parallel()

	// Create a wide directory tree to exercise parallel goroutine-per-subdirectory traversal.
	// Each of the 20 top-level dirs contains 5 subdirs, each with a target file.
	tmpDir := t.TempDir()

	expectedFiles := make(map[string]struct{})
	for i := 0; i < 20; i++ {
		for j := 0; j < 5; j++ {
			dirPath := filepath.Join(tmpDir, fmt.Sprintf("top%02d", i), fmt.Sprintf("sub%02d", j))
			require.NoError(t, os.MkdirAll(dirPath, 0755))
			filePath := filepath.Join(dirPath, ".env")
			require.NoError(t, os.WriteFile(filePath, []byte("content"), 0644))
			expectedFiles[filePath] = struct{}{}
		}
	}

	patterns := []Pattern{
		{
			Name:     "env_files",
			Patterns: []string{".env"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	envFiles := index.Get("env_files")
	assert.Len(t, envFiles, 100)

	// Verify every expected file was found
	for _, f := range envFiles {
		_, ok := expectedFiles[f]
		assert.True(t, ok, "unexpected file in results: %s", f)
	}
}

func TestBuildIndex_Concurrent_MultipleBaseDirs(t *testing.T) {
	t.Parallel()

	// Create multiple base directories
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()
	tmpDir3 := t.TempDir()

	// Create files in each directory
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir1, ".gitconfig"), []byte("cfg1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir2, ".gitconfig"), []byte("cfg2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir3, ".gitconfig"), []byte("cfg3"), 0644))

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig"},
			Type:     PatternTypeExact,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir1, tmpDir2, tmpDir3},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	// Should find all three gitconfig files
	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 3)
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir1, ".gitconfig"))
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir2, ".gitconfig"))
	assert.Contains(t, gitconfigs, filepath.Join(tmpDir3, ".gitconfig"))
}

func TestBuildIndex_WithExcludePaths(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a structure with files in both an included and an excluded directory
	includedDir := filepath.Join(tmpDir, "home")
	excludedDir := filepath.Join(tmpDir, "repos")

	for _, dir := range []string{includedDir, filepath.Join(includedDir, ".ssh"), excludedDir, filepath.Join(excludedDir, "proj", ".ssh")} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	require.NoError(t, os.WriteFile(filepath.Join(includedDir, ".gitconfig"), []byte("included"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(includedDir, ".ssh", "config"), []byte("included"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(excludedDir, ".gitconfig"), []byte("excluded"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(excludedDir, "proj", ".ssh", "config"), []byte("excluded"), 0644))

	patterns := []Pattern{
		{
			Name:     "gitconfig",
			Patterns: []string{".gitconfig"},
			Type:     PatternTypeExact,
		},
		{
			Name:     "ssh_config",
			Patterns: []string{".ssh/config"},
			Type:     PatternTypeGlob,
		},
	}

	input := BuildIndexInput{
		BaseDirs:       []string{tmpDir},
		ExcludePaths:   []string{excludedDir},
		Patterns:       patterns,
		MaxDepth:       0,
		FollowSymlinks: false,
	}

	ctx := context.Background()
	index, err := BuildIndex(ctx, input)
	require.NoError(t, err)

	// Only files outside the excluded directory should be found
	gitconfigs := index.Get("gitconfig")
	assert.Len(t, gitconfigs, 1)
	assert.Contains(t, gitconfigs, filepath.Join(includedDir, ".gitconfig"))
	assert.NotContains(t, gitconfigs, filepath.Join(excludedDir, ".gitconfig"))

	sshConfigs := index.Get("ssh_config")
	assert.Len(t, sshConfigs, 1)
	assert.Contains(t, sshConfigs, filepath.Join(includedDir, ".ssh", "config"))
	assert.NotContains(t, sshConfigs, filepath.Join(excludedDir, "proj", ".ssh", "config"))
}

func TestBuildIndex_WithBasenameExcludes(t *testing.T) {
	t.Parallel()

	// Bare names in ExcludePaths prune any directory whose basename matches,
	// at any depth — the common case is "node_modules".
	tmpDir := t.TempDir()

	for _, dir := range []string{
		filepath.Join(tmpDir, "proj1"),
		filepath.Join(tmpDir, "proj1", "node_modules", "pkg"),
		filepath.Join(tmpDir, "proj2", "sub", "node_modules", "deep"),
		filepath.Join(tmpDir, "node_modules"),
		filepath.Join(tmpDir, "keep_me"),
	} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	files := []string{
		filepath.Join(tmpDir, "proj1", ".env"),                                // keep
		filepath.Join(tmpDir, "proj1", "node_modules", "pkg", ".env"),         // prune
		filepath.Join(tmpDir, "proj2", "sub", "node_modules", "deep", ".env"), // prune
		filepath.Join(tmpDir, "node_modules", ".env"),                         // prune
		filepath.Join(tmpDir, "keep_me", ".env"),                              // keep
	}
	for _, f := range files {
		require.NoError(t, os.WriteFile(f, []byte("x"), 0644))
	}

	input := BuildIndexInput{
		BaseDirs:     []string{tmpDir},
		ExcludePaths: []string{"node_modules"},
		Patterns: []Pattern{
			{Name: "env_files", Patterns: []string{".env"}, Type: PatternTypeExact},
		},
	}

	index, err := BuildIndex(context.Background(), input)
	require.NoError(t, err)

	envs := index.Get("env_files")
	assert.Len(t, envs, 2)
	assert.Contains(t, envs, filepath.Join(tmpDir, "proj1", ".env"))
	assert.Contains(t, envs, filepath.Join(tmpDir, "keep_me", ".env"))
}
