// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package progress decouples long-running operations (such as the file-index
// crawl) from how their progress is surfaced. An operation reports through the
// Reporter interface; the caller supplies an implementation — a terminal
// spinner, a daemon event stream, or NoOp — so the operation never depends on
// a particular UI.
package progress

// Reporter observes the progress of a long-running operation.
type Reporter interface {
	// Start signals the operation has begun. A reporter may lazily create its
	// display here, so nothing is shown when the operation is skipped (for
	// example a cache hit that never starts a crawl).
	Start()
	// Update reports the cumulative number of items processed so far.
	Update(processed int64)
	// Done signals the operation finished; the reporter flushes or closes.
	Done()
}

// NoOp is a Reporter that discards all progress. It is the zero-cost default
// for headless consumers (daemon, tests, machine-readable output).
type NoOp struct{}

// Start does nothing.
func (NoOp) Start() {}

// Update does nothing.
func (NoOp) Update(int64) {}

// Done does nothing.
func (NoOp) Done() {}
