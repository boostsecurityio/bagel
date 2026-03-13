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

// NPMProbe checks NPM and Yarn configuration for security issues
type NPMProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewNPMProbe creates a new NPM probe
func NewNPMProbe(config models.ProbeSettings, registry *detector.Registry) *NPMProbe {
	return &NPMProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *NPMProbe) Name() string {
	return "npm"
}

// IsEnabled returns whether the probe is enabled
func (p *NPMProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *NPMProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *NPMProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the NPM probe
func (p *NPMProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping NPM probe")
		return findings, nil
	}

	// Get npmrc files from file index
	npmrcFiles := p.fileIndex.Get("npmrc")
	yarnrcFiles := p.fileIndex.Get("yarnrc")

	allConfigFiles := append(npmrcFiles, yarnrcFiles...)

	log.Ctx(ctx).Debug().
		Int("npmrc_count", len(npmrcFiles)).
		Int("yarnrc_count", len(yarnrcFiles)).
		Msg("Found NPM/Yarn config files")

	// Process each config file
	for _, filePath := range allConfigFiles {
		fileFindings := p.processConfigFile(ctx, filePath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// processConfigFile reads and analyzes a single NPM/Yarn config file
func (p *NPMProbe) processConfigFile(ctx context.Context, filePath string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

	// Read file contents
	content, err := os.ReadFile(filePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", filePath).
			Msg("Cannot read NPM config file")
		return findings
	}

	contentStr := string(content)

	// Parse config and check for security issues
	configMap := parseNPMConfig(contentStr)
	findings = append(findings, p.checkNPMConfig(filePath, configMap)...)

	// Scan for embedded secrets using detector registry
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + filePath,
		ProbeName: p.Name(),
	})
	detectedSecrets := p.detectorRegistry.DetectAll(contentStr, detCtx)
	findings = append(findings, detectedSecrets...)

	return findings
}

// parseNPMConfig parses NPM/Yarn config into a map
func parseNPMConfig(content string) map[string]string {
	config := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Try parsing as key=value first (npmrc format)
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Remove quotes if present
				value = strings.Trim(value, "\"'")
				config[key] = value
				continue
			}
		}

		// Try parsing as key: value (YAML-style for Yarn v2+)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				// Remove quotes if present
				value = strings.Trim(value, "\"'")
				config[key] = value
			}
		}
	}

	return config
}

// checkNPMConfig checks for insecure NPM/Yarn configuration settings
func (p *NPMProbe) checkNPMConfig(filePath string, config map[string]string) []models.Finding {
	findings := make([]models.Finding, 0, 4)

	// Check for SSL verification disabled
	findings = append(findings, p.checkStrictSSL(filePath, config)...)

	// Check for insecure registries
	findings = append(findings, p.checkInsecureRegistry(filePath, config)...)

	// Check for always-auth disabled
	findings = append(findings, p.checkAlwaysAuth(filePath, config)...)

	return findings
}

// checkStrictSSL checks for disabled SSL verification
func (p *NPMProbe) checkStrictSSL(filePath string, config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["strict-ssl"]; ok && strings.ToLower(value) == "false" {
		findings = append(findings, models.Finding{
			ID:          "npm-ssl-verify-disabled",
			Type:        models.FindingTypeMisconfiguration,
			Fingerprint: models.FingerprintFromFields("npm-ssl-verify-disabled", filePath),
			Probe:       p.Name(),
			Severity:    "high",
			Title:       "NPM SSL Verification Disabled",
			Message: "NPM is configured to skip SSL certificate verification (strict-ssl=false). " +
				"This makes you vulnerable to man-in-the-middle attacks when installing packages from registries.",
			Path: filePath,
			Metadata: map[string]interface{}{
				"config_key":   "strict-ssl",
				"config_value": value,
			},
		})
	}

	return findings
}

// checkInsecureRegistry checks for HTTP (non-HTTPS) registries
func (p *NPMProbe) checkInsecureRegistry(filePath string, config map[string]string) []models.Finding {
	var findings []models.Finding

	for key, value := range config {
		// Check for registry configuration
		if key == "registry" || strings.Contains(key, "registry") {
			if strings.HasPrefix(value, "http://") {
				findings = append(findings, models.Finding{
					ID:          "npm-insecure-registry",
					Type:        models.FindingTypeMisconfiguration,
					Fingerprint: models.FingerprintFromFields("npm-insecure-registry", filePath, key),
					Probe:       p.Name(),
					Severity:    "high",
					Title:       "NPM Insecure Registry Configured",
					Message: "NPM is configured to use an insecure HTTP registry. " +
						"This allows packages to be intercepted or modified in transit. Use HTTPS registries only.",
					Path: filePath,
					Metadata: map[string]interface{}{
						"config_key":   key,
						"config_value": value,
					},
				})
			}
		}
	}

	return findings
}

// checkAlwaysAuth checks for always-auth configuration
func (p *NPMProbe) checkAlwaysAuth(filePath string, config map[string]string) []models.Finding {
	var findings []models.Finding

	if value, ok := config["always-auth"]; ok && strings.ToLower(value) == "true" {
		// This is informational - always-auth can be legitimate but worth noting
		findings = append(findings, models.Finding{
			ID:          "npm-always-auth-enabled",
			Type:        models.FindingTypeMisconfiguration,
			Fingerprint: models.FingerprintFromFields("npm-always-auth-enabled", filePath),
			Probe:       p.Name(),
			Severity:    "low",
			Title:       "NPM Always-Auth Enabled",
			Message: "NPM is configured to always require authentication (always-auth=true). " +
				"While this can be secure, ensure your authentication tokens are properly protected " +
				"and not accidentally committed to version control.",
			Path: filePath,
			Metadata: map[string]interface{}{
				"config_key":   "always-auth",
				"config_value": value,
			},
		})
	}

	return findings
}
