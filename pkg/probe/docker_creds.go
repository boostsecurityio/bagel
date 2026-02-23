// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// DockerCredsProbe checks for Docker registry creds in cleartext
type DockerCredsProbe struct {
	enabled   bool
	config    models.ProbeSettings
	fileIndex *fileindex.FileIndex
}

// NewDockerCredsProbe creates a new cloud credentials probe
func NewDockerCredsProbe(config models.ProbeSettings) *DockerCredsProbe {
	return &DockerCredsProbe{
		enabled: config.Enabled,
		config:  config,
	}
}

// Name returns the probe name
func (dcp *DockerCredsProbe) Name() string {
	return "Docker credentials"
}

// IsEnabled returns whether the probe is enabled
func (dcp *DockerCredsProbe) IsEnabled() bool {
	return dcp.enabled
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (dcp *DockerCredsProbe) SetFileIndex(index *fileindex.FileIndex) {
	dcp.fileIndex = index
}

// Execute runs the Docker credentials probe
func (dcp *DockerCredsProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if dcp.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", dcp.Name()).
			Msg("File index not available, skipping Docker credentials probe")
		return findings, nil
	}

	locations := dcp.fileIndex.Get("docker_config")
	for _, location := range locations {
		_, err := os.Stat(location)
		if err != nil {
			continue
		}
		fileContents, err := os.ReadFile(location)
		if err != nil {
			return findings, err
		}
		registries, err := regsWithCreds(fileContents)
		if err != nil {
			return findings, err
		}
		for _, registry := range registries {
			findings = append(findings, models.Finding{
				ID:        fmt.Sprintf("%s:%s", location, registry),
				Probe:     dcp.Name(),
				Title:     "Docker credentials found",
				Message:   fmt.Sprintf("%s contains cleartext credentials for %s. Consider using a credential helper.", location, registry),
				Path:      location,
				Severity:  "high",
				Locations: locations,
			})
		}
	}
	return findings, nil
}

func regsWithCreds(fileContents []byte) ([]string, error) {
	var registries []string
	var config map[string]interface{}
	if err := json.Unmarshal(fileContents, &config); err != nil {
		return registries, err
	}
	auths, ok := config["auths"].(map[string]interface{})
	if !ok {
		return registries, nil
	}
	for registry, settings := range auths {
		propsForRegistry, ok := settings.(map[string]interface{})
		if !ok {
			continue
		}
		if propsForRegistry["auth"] != nil {
			registries = append(registries, registry)
		}
	}
	return registries, nil
}
