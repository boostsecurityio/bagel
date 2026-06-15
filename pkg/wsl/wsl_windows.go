//go:build windows

// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package wsl

import (
	"context"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/registry"
)

// lxssKey is where WSL records every registered distro, one subkey (a GUID)
// per distro carrying a DistributionName value.
const lxssKey = `Software\Microsoft\Windows\CurrentVersion\Lxss`

// Homes discovers the Linux home directory roots of every registered WSL
// distro reachable from this Windows host. It returns UNC base directories
// (e.g. \\wsl.localhost\Ubuntu\home and \\wsl.localhost\Ubuntu\root) suitable
// for the file index. Distros that are not currently reachable are skipped
// with a warning rather than failing the scan.
func Homes(ctx context.Context) []string {
	distros := registeredDistros(ctx)
	if len(distros) == 0 {
		return nil
	}

	var dirs []string
	for _, distro := range distros {
		if skipDistro(distro) {
			continue
		}
		root, ok := reachableRoot(distro)
		if !ok {
			log.Ctx(ctx).Warn().
				Str("distro", distro).
				Msg("WSL distro registered but filesystem not reachable; skipping (is it installed/startable?)")
			continue
		}
		// /home holds per-user homes; /root is the root user's home. Both are
		// walked relative to these base dirs by the existing patterns.
		dirs = append(dirs, filepath.Join(root, "home"), filepath.Join(root, "root"))
		log.Ctx(ctx).Info().
			Str("distro", distro).
			Str("root", root).
			Msg("Discovered WSL distro for scanning")
	}
	return dirs
}

// registeredDistros reads the distro names recorded under the Lxss registry key.
func registeredDistros(ctx context.Context) []string {
	key, err := registry.OpenKey(registry.CURRENT_USER, lxssKey, registry.READ)
	if err != nil {
		// No key means WSL has never been installed — expected, not an error.
		log.Ctx(ctx).Debug().Err(err).Msg("No WSL registry key; skipping WSL discovery")
		return nil
	}
	defer func() { _ = key.Close() }()

	guids, err := key.ReadSubKeyNames(-1)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("Failed to enumerate WSL distros")
		return nil
	}

	var names []string
	for _, guid := range guids {
		sub, err := registry.OpenKey(key, guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, err := sub.GetStringValue("DistributionName")
		_ = sub.Close()
		if err != nil || name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

// reachableRoot returns the first UNC root for the distro that exists,
// auto-starting the distro's file server as a side effect of the stat.
func reachableRoot(distro string) (string, bool) {
	for _, root := range uncCandidates(distro) {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root, true
		}
	}
	return "", false
}
