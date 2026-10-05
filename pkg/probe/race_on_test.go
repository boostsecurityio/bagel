// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build race

package probe

// The race detector changes escape analysis, so allocation counts are only
// meaningful without it.
const raceEnabled = true
