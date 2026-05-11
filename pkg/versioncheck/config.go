// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package versioncheck implements a lightweight, opt-out version-check that
// reports anonymous start telemetry to the Boost OSS telemetry endpoint and
// notifies the user when a newer bagel release is available.
package versioncheck

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/boostsecurityio/bagel/pkg/config"
	"gopkg.in/yaml.v3"
)

// State is the user-level data persisted between bagel invocations to support
// the once-per-day version check. It is intentionally separate from the
// project-level bagel.yaml so that bagel.yaml stays user-managed.
type State struct {
	InstanceID             string    `yaml:"instance_id,omitempty"`
	StartCount             int       `yaml:"start_count,omitempty"`
	LastReportedStartCount int       `yaml:"last_reported_start_count,omitempty"`
	LastVersionCheckAt     time.Time `yaml:"last_version_check_timestamp,omitempty"`
}

// StatePath returns the path to the version-check state file. It honors
// BAGEL_CONFIG_DIR for tests and constrained environments and otherwise
// defaults to <config-dir>/version-check.yaml, where the config dir is the
// platform-appropriate location returned by config.GetConfigDir.
func StatePath() string {
	if dir := os.Getenv("BAGEL_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "version-check.yaml")
	}
	return filepath.Join(config.GetConfigDir(), "version-check.yaml")
}

// LoadState reads the version-check state file. A missing file is not an
// error and yields a nil State so callers can treat it as a first run.
func LoadState() (*State, error) {
	path := StatePath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read version-check state %s: %w", path, err)
	}

	var s State
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("invalid version-check state: %w", err)
	}
	return &s, nil
}

// SaveState writes the version-check state file, creating the parent
// directory when needed. The file is written with restrictive permissions
// because it holds an anonymous instance identifier.
func SaveState(s *State) error {
	path := StatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create version-check state dir: %w", err)
	}
	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal version-check state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write version-check state %s: %w", path, err)
	}
	return nil
}
