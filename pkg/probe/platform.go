// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"path/filepath"
	"runtime"
	"strings"
)

// IsNullDevice checks if a path refers to the null device on any platform.
// On Unix: /dev/null
// On Windows: nul, NUL, C:\nul, \\.\nul, etc.
// This function detects both Unix and Windows null device patterns regardless of
// the current platform, because config files may be shared across systems.
func IsNullDevice(path string) bool {
	lower := strings.ToLower(path)

	// Unix null device
	if strings.Contains(lower, "/dev/null") {
		return true
	}

	// Windows null device (NUL) - check on all platforms for config file portability
	// Windows NUL can appear as: nul, NUL, C:\nul, \\.\nul
	// Use filepath.Base for forward slash paths, but also handle backslash manually
	// since filepath.Base on Unix doesn't recognize backslash as separator
	base := strings.ToLower(filepath.Base(path))
	if base == "nul" {
		return true
	}

	// Handle Windows-style backslash paths (e.g., "C:\nul") on Unix
	if idx := strings.LastIndex(lower, "\\"); idx != -1 {
		base = lower[idx+1:]
		if base == "nul" {
			return true
		}
	}

	return false
}

// GetPermissionFixMessage returns a platform-appropriate message for fixing file permissions.
func GetPermissionFixMessage(filePath string) string {
	if runtime.GOOS == "windows" {
		return "Restrict access using: icacls \"" + filePath + "\" /inheritance:r /grant:r \"%USERNAME%\":R"
	}
	return "Fix with: chmod 600 " + filePath
}
