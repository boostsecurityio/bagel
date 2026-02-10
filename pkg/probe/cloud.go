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

// CloudProbe checks cloud provider credential files
type CloudProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewCloudProbe creates a new cloud credentials probe
func NewCloudProbe(config models.ProbeSettings, registry *detector.Registry) *CloudProbe {
	return &CloudProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *CloudProbe) Name() string {
	return "cloud"
}

// IsEnabled returns whether the probe is enabled
func (p *CloudProbe) IsEnabled() bool {
	return p.enabled
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *CloudProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the cloud probe
func (p *CloudProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping cloud probe")
		return findings, nil
	}

	// Get cloud credential files from file index
	awsConfig := p.fileIndex.Get("aws_config")
	awsCredentials := p.fileIndex.Get("aws_credentials")
	gcpConfig := p.fileIndex.Get("gcp_config")
	gcpCredentials := p.fileIndex.Get("gcp_credentials")
	azureConfig := p.fileIndex.Get("azure_config")

	log.Ctx(ctx).Debug().
		Int("aws_config_count", len(awsConfig)).
		Int("aws_credentials_count", len(awsCredentials)).
		Int("gcp_config_count", len(gcpConfig)).
		Int("gcp_credentials_count", len(gcpCredentials)).
		Int("azure_config_count", len(azureConfig)).
		Msg("Found cloud credential files")

	// Process AWS files
	for _, filePath := range awsConfig {
		fileFindings := p.processCloudFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}
	for _, filePath := range awsCredentials {
		fileFindings := p.processCloudFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	// Process GCP files
	for _, filePath := range gcpConfig {
		fileFindings := p.processCloudFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}
	for _, filePath := range gcpCredentials {
		fileFindings := p.processCloudFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	// Process Azure files
	for _, filePath := range azureConfig {
		fileFindings := p.processCloudFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// processCloudFile reads and analyzes a cloud credential file
func (p *CloudProbe) processCloudFile(ctx context.Context, filePath string) []models.Finding {
	var findings []models.Finding

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read cloud credential file")
		return findings
	}

	contentStr := string(content)

	// Use detector registry to scan for cloud credentials
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	detectedCreds := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedCreds...)

	return findings
}
