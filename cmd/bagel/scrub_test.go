// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUniqueFilePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		findings []models.Finding
		want     []string
	}{
		{
			name:     "empty findings",
			findings: nil,
			want:     []string{},
		},
		{
			name: "single file",
			findings: []models.Finding{
				{Path: "file:/home/user/.bash_history"},
			},
			want: []string{"/home/user/.bash_history"},
		},
		{
			name: "deduplicates same file",
			findings: []models.Finding{
				{Path: "file:/home/user/.bash_history"},
				{Path: "file:/home/user/.bash_history"},
			},
			want: []string{"/home/user/.bash_history"},
		},
		{
			name: "multiple distinct files",
			findings: []models.Finding{
				{Path: "file:/home/user/.bash_history"},
				{Path: "file:/home/user/.zsh_history"},
			},
			want: []string{
				"/home/user/.bash_history",
				"/home/user/.zsh_history",
			},
		},
		{
			name: "path without file prefix",
			findings: []models.Finding{
				{Path: "/home/user/.bash_history"},
			},
			want: []string{"/home/user/.bash_history"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := uniqueFilePaths(tt.findings)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFilterByGracePeriod(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create an old file (2 hours ago)
	oldFile := filepath.Join(dir, "old.jsonl")
	require.NoError(t, os.WriteFile(oldFile, []byte("data"), 0600))
	oldTime := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(oldFile, oldTime, oldTime))

	// Create a recent file (just now)
	newFile := filepath.Join(dir, "new.jsonl")
	require.NoError(t, os.WriteFile(newFile, []byte("data"), 0600))

	t.Run("filters recent files", func(t *testing.T) {
		t.Parallel()
		result := filterByGracePeriod([]string{oldFile, newFile}, 60)
		assert.Contains(t, result, oldFile)
		assert.NotContains(t, result, newFile)
	})

	t.Run("grace zero includes all", func(t *testing.T) {
		t.Parallel()
		result := filterByGracePeriod([]string{oldFile, newFile}, 0)
		assert.Contains(t, result, oldFile)
		assert.Contains(t, result, newFile)
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		result := filterByGracePeriod(nil, 60)
		assert.Empty(t, result)
	})

	t.Run("nonexistent file skipped", func(t *testing.T) {
		t.Parallel()
		result := filterByGracePeriod([]string{"/nonexistent/path"}, 60)
		assert.Empty(t, result)
	})
}
