// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// PyPIProbe checks PyPI and pip configuration for security issues
type PyPIProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewPyPIProbe creates a new PyPI probe
func NewPyPIProbe(config models.ProbeSettings, registry *detector.Registry) *PyPIProbe {
	return &PyPIProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *PyPIProbe) Name() string {
	return "pypi"
}

// IsEnabled returns whether the probe is enabled
func (p *PyPIProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *PyPIProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *PyPIProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the PyPI probe
func (p *PyPIProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping PyPI probe")
		return findings, nil
	}

	pypirc := p.fileIndex.Get("pypirc")
	pipConfigs := p.fileIndex.Get("pip_config")

	log.Ctx(ctx).Debug().
		Int("pypirc_count", len(pypirc)).
		Int("pip_config_count", len(pipConfigs)).
		Msg("Found PyPI/pip config files")

	for _, filePath := range pypirc {
		findings = append(findings, p.processPyPIRC(ctx, filePath)...)
	}

	for _, filePath := range pipConfigs {
		findings = append(findings, p.processPipConfig(ctx, filePath)...)
	}

	return findings, nil
}

// processPyPIRC reads and analyzes a .pypirc file
func (p *PyPIProbe) processPyPIRC(ctx context.Context, filePath string) []models.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read .pypirc file")
		return nil
	}

	contentStr := string(content)
	findings := make([]models.Finding, 0, 4)

	// Check for misconfigurations
	configMap := parsePyPIRC(contentStr)
	findings = append(findings, p.checkPyPIConfig(filePath, configMap)...)

	// Scan for embedded secrets using detector registry
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	findings = append(findings, p.detectorRegistry.DetectAll(contentStr, detCtx)...)

	return findings
}

// processPipConfig reads and analyzes a pip.conf/pip.ini file
func (p *PyPIProbe) processPipConfig(ctx context.Context, filePath string) []models.Finding {
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read pip config file")
		return nil
	}

	contentStr := string(content)
	findings := make([]models.Finding, 0, 4)

	// Check for index URLs with embedded credentials
	configMap := parsePyPIRC(contentStr)
	findings = append(findings, p.checkPipConfig(filePath, configMap)...)

	// Scan for embedded secrets
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	findings = append(findings, p.detectorRegistry.DetectAll(contentStr, detCtx)...)

	return findings
}

// parsePyPIRC parses an INI-style config file into a key-value map.
// Section headers are ignored; keys are lowercased for consistent lookup.
func parsePyPIRC(content string) map[string]string {
	config := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, comments, and section headers
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}

		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			config[strings.ToLower(key)] = value
		}
	}

	return config
}

// checkPyPIConfig checks .pypirc for insecure settings
func (p *PyPIProbe) checkPyPIConfig(filePath string, config map[string]string) []models.Finding {
	var findings []models.Finding

	// Check for plaintext passwords
	if _, ok := config["password"]; ok {
		findings = append(findings, models.Finding{
			ID:          "pypi-plaintext-password",
			Type:        models.FindingTypeMisconfiguration,
			Fingerprint: models.FingerprintFromFields("pypi-plaintext-password", filePath),
			Probe:       p.Name(),
			Severity:    "high",
			Title:       "PyPI Plaintext Password in .pypirc",
			Description: "A plaintext password was found in .pypirc. " +
				"Use PyPI API tokens instead of passwords, and consider using keyring for storage.",
			Message: fmt.Sprintf("In %s: password field contains a plaintext credential", filePath),
			Path:    filePath,
			Metadata: map[string]interface{}{
				"config_key": "password",
			},
		})
	}

	// Check for insecure repository URLs
	if repo, ok := config["repository"]; ok && strings.HasPrefix(repo, "http://") {
		findings = append(findings, models.Finding{
			ID:          "pypi-insecure-repository",
			Type:        models.FindingTypeMisconfiguration,
			Fingerprint: models.FingerprintFromFields("pypi-insecure-repository", filePath, repo),
			Probe:       p.Name(),
			Severity:    "high",
			Title:       "PyPI Insecure Repository URL",
			Description: "An HTTP repository URL was found. HTTP URLs allow packages and credentials to be intercepted in transit. Use HTTPS.",
			Message:     fmt.Sprintf("In %s: repository=%s", filePath, repo),
			Path:        filePath,
			Metadata: map[string]interface{}{
				"config_key":   "repository",
				"config_value": repo,
			},
		})
	}

	return findings
}

// checkPipConfig checks pip.conf for insecure settings
func (p *PyPIProbe) checkPipConfig(filePath string, config map[string]string) []models.Finding {
	var findings []models.Finding

	// Check index-url and extra-index-url for embedded credentials
	for _, key := range []string{"index-url", "extra-index-url"} {
		if value, ok := config[key]; ok {
			if strings.Contains(value, "@") && strings.HasPrefix(value, "http") {
				findings = append(findings, models.Finding{
					ID:          "pip-index-embedded-credentials",
					Type:        models.FindingTypeMisconfiguration,
					Fingerprint: models.FingerprintFromFields("pip-index-embedded-credentials", filePath, key),
					Probe:       p.Name(),
					Severity:    "high",
					Title:       "Pip Index URL Contains Embedded Credentials",
					Description: "Embedded credentials were found in a pip index URL. " +
						"Use keyring or environment variables for authentication instead.",
					Message: fmt.Sprintf("In %s: %s contains embedded credentials", filePath, key),
					Path:    filePath,
					Metadata: map[string]interface{}{
						"config_key": key,
					},
				})
			}
		}
	}

	return findings
}
