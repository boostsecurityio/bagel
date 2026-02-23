// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// DockerCredsProbe checks for Docker registry creds in cleartext
type DockerCredsProbe struct {
	enabled          bool
	config           models.ProbeSettings
	fileIndex        *fileindex.FileIndex
	detectorRegistry *detector.Registry
}

// NewDockerCredsProbe creates a new cloud credentials probe
func NewDockerCredsProbe(config models.ProbeSettings, registry *detector.Registry) *DockerCredsProbe {
	return &DockerCredsProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
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
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "file:" + location,
			ProbeName: dcp.Name(),
		})
		detectedSecrets := dcp.detectorRegistry.DetectAll(string(fileContents), detCtx)
		findings = append(findings, detectedSecrets...)
	}
	return findings, nil
}
