// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/collector"
	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/logger"
)

// BenchmarkScanNoCache runs the same code path as `bagel scan --no-cache`
func BenchmarkScanNoCache(b *testing.B) {
	log := logger.Setup(false)
	ctx := log.WithContext(context.Background())

	cfg, err := config.Load("")
	if err != nil {
		b.Fatal(err)
	}
	probes := initializeProbes(cfg)

	for b.Loop() {
		col := collector.New(collector.NewInput{
			Probes:     probes,
			Config:     cfg,
			NoCache:    true,
			NoProgress: true,
		})
		if _, err := col.Collect(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
