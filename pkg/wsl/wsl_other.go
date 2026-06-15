//go:build !windows

// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package wsl

import "context"

// Homes is a no-op off Windows: WSL filesystems are only reachable from a
// Windows host. ponytail: stub, real discovery lives in wsl_windows.go.
func Homes(_ context.Context) []string { return nil }
