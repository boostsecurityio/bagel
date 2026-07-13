// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/boostsecurityio/bagel/pkg/cache"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/boostsecurityio/bagel/pkg/progress"
	"github.com/boostsecurityio/bagel/pkg/wsl"
	"github.com/rs/zerolog/log"
)

// BuildFileIndex builds the file index for cfg's file-index settings and, when
// store is non-nil, serves it from (and saves it to) the cache. It is the
// canonical crawl the collector runs internally, exported so a caller can own
// the crawl and inject the result via NewInput.FileIndex — sharing a single
// index across bagel's probes and the caller's own consumers.
//
// reporter observes crawl progress; pass progress.NoOp{} (or nil) for none. A
// cache hit returns without starting the reporter, so no progress is shown when
// no crawl happens.
func BuildFileIndex(ctx context.Context, cfg *models.Config, store *cache.Store, reporter progress.Reporter) (*fileindex.FileIndex, error) {
	if reporter == nil {
		reporter = progress.NoOp{}
	}
	logger := log.Ctx(ctx)

	patterns := make([]fileindex.Pattern, 0, len(cfg.FileIndex.Patterns))
	for _, p := range cfg.FileIndex.Patterns {
		patterns = append(patterns, fileindex.Pattern{
			Name:     p.Name,
			Patterns: p.Patterns,
			Type:     fileindex.PatternType(p.Type),
		})
	}

	baseDirs := cfg.FileIndex.BaseDirs
	// On Windows, append the home dirs of installed WSL distros so Linux
	// secrets behind WSL aren't a blindspot. No-op on other platforms.
	if cfg.FileIndex.ScanWSL {
		if wslDirs := wsl.Homes(ctx); len(wslDirs) > 0 {
			baseDirs = append(append([]string{}, baseDirs...), wslDirs...)
		}
	}

	// Serve from cache when available.
	if store != nil {
		ttl, _ := time.ParseDuration(cfg.FileIndex.Cache.TTL)
		index, err := store.Load(ctx, cache.LoadInput{
			BaseDirs:       baseDirs,
			ExcludePaths:   cfg.FileIndex.ExcludePaths,
			Patterns:       patterns,
			MaxDepth:       cfg.FileIndex.MaxDepth,
			FollowSymlinks: cfg.FileIndex.FollowSymlinks,
			TTL:            ttl,
			ValidateFiles:  cfg.FileIndex.Cache.ValidateOnLoad,
		})
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to load file index from cache")
		}
		if index != nil {
			return index, nil
		}
	}

	// Cache miss (or caching disabled): crawl.
	reporter.Start()
	indexStartTime := time.Now()
	index, err := fileindex.BuildIndex(ctx, fileindex.BuildIndexInput{
		BaseDirs:         baseDirs,
		ExcludePaths:     cfg.FileIndex.ExcludePaths,
		Patterns:         patterns,
		MaxDepth:         cfg.FileIndex.MaxDepth,
		FollowSymlinks:   cfg.FileIndex.FollowSymlinks,
		NumWorkers:       cfg.Resources.FileIndexWorkers,
		ProgressCallback: reporter.Update,
	})
	reporter.Done()
	if err != nil {
		return nil, fmt.Errorf("build file index: %w", err)
	}

	logger.Info().
		Dur("duration", time.Since(indexStartTime)).
		Int("total_files", index.TotalFiles()).
		Msg("File index built successfully")

	// Save to cache (best effort).
	if store != nil {
		if err := store.Save(ctx, cache.SaveInput{
			BaseDirs:       baseDirs,
			ExcludePaths:   cfg.FileIndex.ExcludePaths,
			Patterns:       patterns,
			MaxDepth:       cfg.FileIndex.MaxDepth,
			FollowSymlinks: cfg.FileIndex.FollowSymlinks,
			Index:          index,
			SampleSize:     cfg.FileIndex.Cache.SampleSize,
		}); err != nil {
			logger.Warn().Err(err).Msg("Failed to save file index to cache")
		}
	}

	return index, nil
}
