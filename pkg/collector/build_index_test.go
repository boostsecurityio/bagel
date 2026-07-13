// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package collector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/cache"
	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingReporter records which Reporter methods were called.
type recordingReporter struct {
	started, done bool
	last          int64
}

func (r *recordingReporter) Start()         { r.started = true }
func (r *recordingReporter) Update(p int64) { r.last = p }
func (r *recordingReporter) Done()          { r.done = true }

// scopedConfig loads defaults, points the crawl at baseDir, and disables WSL.
func scopedConfig(t *testing.T, baseDir string) *models.Config {
	t.Helper()
	cfg, err := config.Load("")
	require.NoError(t, err)
	cfg.FileIndex.BaseDirs = []string{baseDir}
	cfg.FileIndex.ScanWSL = false
	return cfg
}

func TestBuildFileIndex_CrawlsAndReports(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("//registry/:_authToken=x\n"), 0o600))

	r := &recordingReporter{}
	idx, err := BuildFileIndex(context.Background(), scopedConfig(t, dir), nil, r)
	require.NoError(t, err)
	require.NotNil(t, idx)

	assert.True(t, r.started, "a crawl should start the reporter")
	assert.True(t, r.done, "a crawl should finish the reporter")
}

func TestBuildFileIndex_CacheHitSkipsReporter(t *testing.T) {
	// Isolate the cache directory across all OS resolutions.
	cacheHome := t.TempDir()
	t.Setenv("HOME", cacheHome)
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("LOCALAPPDATA", cacheHome)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".npmrc"), []byte("//registry/:_authToken=x\n"), 0o600))
	cfg := scopedConfig(t, dir)

	store, err := cache.NewStore()
	require.NoError(t, err)

	// First build populates the cache and crawls.
	first := &recordingReporter{}
	_, err = BuildFileIndex(context.Background(), cfg, store, first)
	require.NoError(t, err)
	require.True(t, first.started, "first build should crawl")

	// Second build must be served from cache — no crawl, so no Start.
	second := &recordingReporter{}
	idx, err := BuildFileIndex(context.Background(), cfg, store, second)
	require.NoError(t, err)
	require.NotNil(t, idx)
	assert.False(t, second.started, "a cache hit must not start the reporter")
}
