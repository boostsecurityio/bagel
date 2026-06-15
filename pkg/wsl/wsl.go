// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package wsl discovers WSL (Windows Subsystem for Linux) distro filesystems
// from a Windows host so their Linux home directories can be scanned for
// secrets. On non-Windows platforms its discovery is a no-op.
package wsl

import "strings"

// UNC prefixes used to reach a running distro's filesystem from Windows.
// \\wsl.localhost\ is the modern form (Windows 11+); \\wsl$\ is the legacy
// fallback. Accessing either auto-starts the distro's 9p file server.
const (
	uncLocalhost = `\\wsl.localhost\`
	uncDollar    = `\\wsl$\`
)

// uncCandidates returns the UNC roots to probe for a distro, newest form first.
func uncCandidates(distro string) []string {
	return []string{uncLocalhost + distro, uncDollar + distro}
}

// skipDistro reports whether a registered distro is an internal/system distro
// that holds no user secrets — Docker Desktop registers backing distros
// (docker-desktop, docker-desktop-data) we don't want to walk.
func skipDistro(name string) bool {
	return strings.HasPrefix(name, "docker-desktop")
}
