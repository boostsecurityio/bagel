// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// WireGuardProbe checks WireGuard VPN configuration files for exposed private keys
type WireGuardProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewWireGuardProbe creates a new WireGuard probe
func NewWireGuardProbe(config models.ProbeSettings, registry *detector.Registry) *WireGuardProbe {
	return &WireGuardProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *WireGuardProbe) Name() string {
	return "wireguard"
}

// IsEnabled returns whether the probe is enabled
func (p *WireGuardProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *WireGuardProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *WireGuardProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the WireGuard probe
func (p *WireGuardProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// Collect config files from file index (user-level: ~/.config/wireguard/)
	var configFiles []string
	if p.fileIndex != nil {
		configFiles = append(configFiles, p.fileIndex.Get("wireguard_config")...)
	}

	// Check system-level paths directly (outside home dir, not covered by file index)
	configFiles = append(configFiles, p.findSystemConfigs(ctx)...)

	log.Ctx(ctx).Debug().
		Int("config_count", len(configFiles)).
		Msg("Found WireGuard config files")

	for _, filePath := range configFiles {
		fileFindings := p.processConfigFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// findSystemConfigs discovers WireGuard configs in system-level directories
func (p *WireGuardProbe) findSystemConfigs(ctx context.Context) []string {
	var systemPaths []string

	switch runtime.GOOS {
	case "linux":
		systemPaths = []string{"/etc/wireguard"}
	case "darwin":
		systemPaths = []string{
			"/opt/homebrew/etc/wireguard",
			"/usr/local/etc/wireguard",
		}
	}

	var configs []string
	for _, dir := range systemPaths {
		matches, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil {
			log.Ctx(ctx).Debug().
				Err(err).
				Str("dir", dir).
				Msg("Cannot glob WireGuard system directory")
			continue
		}
		configs = append(configs, matches...)
	}

	return configs
}

// processConfigFile reads a WireGuard config and scans for private keys.
// WireGuard configs are INI-format with PrivateKey on a single line, so
// per-line scanning attaches a line number to each finding.
func (p *WireGuardProbe) processConfigFile(ctx context.Context, filePath string) []models.Finding {
	return scanFileLines(ctx, filePath, p.Name(), p.detectorRegistry, 0)
}
