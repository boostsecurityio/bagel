// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"

	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
)

// Probe defines the interface that all probes must implement
type Probe interface {
	// Name returns the name of the probe (e.g., "git", "ssh", "npm")
	Name() string

	// Execute runs the probe and returns findings
	Execute(ctx context.Context) ([]models.Finding, error)

	// IsEnabled returns whether the probe is enabled
	IsEnabled() bool
}

// FileIndexAware is an optional interface that probes can implement
// to receive the pre-built file index before execution
type FileIndexAware interface {
	// SetFileIndex provides the file index to the probe
	SetFileIndex(index *fileindex.FileIndex)
}

// Result represents the output of a probe execution
type Result struct {
	ProbeName string
	Findings  []models.Finding
	Error     error
}
