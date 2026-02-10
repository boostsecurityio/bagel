// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// EnvProbe checks environment variables for security issues
type EnvProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewEnvProbe creates a new environment variable probe
func NewEnvProbe(config models.ProbeSettings, registry *detector.Registry) *EnvProbe {
	return &EnvProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *EnvProbe) Name() string {
	return "env"
}

// IsEnabled returns whether the probe is enabled
func (p *EnvProbe) IsEnabled() bool {
	return p.enabled
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *EnvProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the environment variable probe
func (p *EnvProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// Get all environment variables
	envVars := os.Environ()

	// Run secret detectors on each environment variable value
	findings = append(findings, p.scanForSecrets(envVars)...)

	// If file index is available, scan shell config and .env files
	if p.fileIndex != nil {
		// Scan shell configuration files
		findings = append(findings, p.scanShellConfigFiles(ctx)...)

		// Scan .env files
		findings = append(findings, p.scanEnvFiles(ctx)...)
	} else {
		log.Ctx(ctx).Debug().
			Str("probe", p.Name()).
			Msg("File index not available, skipping file scans")
	}

	return findings, nil
}

// scanForSecrets uses the detector registry to scan environment variable values for secrets
func (p *EnvProbe) scanForSecrets(envVars []string) []models.Finding {
	var findings []models.Finding

	for _, envVar := range envVars {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) != 2 {
			continue
		}

		varName := parts[0]
		varValue := parts[1]

		// Skip empty values
		if varValue == "" {
			continue
		}

		// Run all detectors on this value
		ctx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "env:" + varName,
			ProbeName: p.Name(),
		}).WithEnvVarName(varName)

		detectedSecrets := p.detectorRegistry.DetectAll(varValue, ctx)
		findings = append(findings, detectedSecrets...)
	}

	return findings
}

// scanShellConfigFiles scans shell configuration files for secrets
func (p *EnvProbe) scanShellConfigFiles(ctx context.Context) []models.Finding {
	var findings []models.Finding

	// Get shell config files from file index
	shellConfigTypes := []string{"bashrc", "zshrc"}

	for _, configType := range shellConfigTypes {
		configFiles := p.fileIndex.Get(configType)

		log.Ctx(ctx).Debug().
			Str("config_type", configType).
			Int("count", len(configFiles)).
			Msg("Found shell config files")

		for _, filePath := range configFiles {
			fileFindings := p.processShellConfigFile(ctx, filePath)
			findings = append(findings, fileFindings...)
		}
	}

	return findings
}

// processShellConfigFile reads and analyzes a shell configuration file
func (p *EnvProbe) processShellConfigFile(ctx context.Context, filePath string) []models.Finding {
	var findings []models.Finding

	// Read file contents
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read shell config file")
		return findings
	}

	contentStr := string(content)

	// Scan entire file content for secrets using detector registry
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	detectedSecrets := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedSecrets...)

	return findings
}

// scanEnvFiles scans .env files for secrets and configuration issues
func (p *EnvProbe) scanEnvFiles(ctx context.Context) []models.Finding {
	var findings []models.Finding

	// Get .env files from file index
	envFiles := p.fileIndex.Get("env_files")

	log.Ctx(ctx).Debug().
		Int("count", len(envFiles)).
		Msg("Found .env files")

	for _, filePath := range envFiles {
		fileFindings := p.processEnvFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	return findings
}

// processEnvFile reads and analyzes a .env file
func (p *EnvProbe) processEnvFile(ctx context.Context, filePath string) []models.Finding {
	var findings []models.Finding

	// Read file contents
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read .env file")
		return findings
	}

	contentStr := string(content)

	// Scan entire file content for secrets using detector registry
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	detectedSecrets := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedSecrets...)

	return findings
}
