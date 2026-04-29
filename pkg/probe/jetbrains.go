// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// JetBrainsProbe checks JetBrains project files for secrets
type JetBrainsProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewJetBrainsProbe creates a new JetBrains probe
func NewJetBrainsProbe(config models.ProbeSettings, registry *detector.Registry) *JetBrainsProbe {
	return &JetBrainsProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *JetBrainsProbe) Name() string {
	return "jetbrains"
}

// IsEnabled returns whether the probe is enabled
func (p *JetBrainsProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *JetBrainsProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *JetBrainsProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute runs the JetBrains probe
func (p *JetBrainsProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping JetBrains probe")
		return findings, nil
	}

	// Get JetBrains workspace files from file index
	workspaceFiles := p.fileIndex.Get("jetbrains")

	log.Ctx(ctx).Debug().
		Int("jetbrains_files_count", len(workspaceFiles)).
		Msg("Found JetBrains files")

	// Process each JetBrains workspace file
	for _, workspacePath := range workspaceFiles {
		fileFindings := p.processWorkspaceFile(ctx, workspacePath)
		findings = append(findings, fileFindings...)
	}

	return findings, nil
}

// processWorkspaceFile reads and scans a JetBrains workspace file for secrets
func (p *JetBrainsProbe) processWorkspaceFile(ctx context.Context, workspacePath string) []models.Finding {
	var findings []models.Finding

	// Open the file
	file, err := os.Open(workspacePath)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", workspacePath).
			Msg("Cannot open JetBrains workspace file")
		return findings
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", workspacePath).
			Msg("Cannot read JetBrains workspace file")
		return findings
	}

	type EnvironmentVariable struct {
		XMLName xml.Name `xml:"env"`
		Name    string   `xml:"name,attr"`
		Value   string   `xml:"value,attr"`
	}

	type EnvironmentVariables struct {
		XMLName   xml.Name              `xml:"envs"`
		Variables []EnvironmentVariable `xml:"env"`
	}

	type ConfigurationParameters struct {
		XMLName xml.Name `xml:"parameters"`
		Value   string   `xml:"value,attr"`
	}

	type Configuration struct {
		XMLName     xml.Name                `xml:"configuration"`
		Name        string                  `xml:"name,attr"`
		Parameters  ConfigurationParameters `xml:"parameters"`
		Environment EnvironmentVariables    `xml:"envs"`
	}

	type Component struct {
		XMLName        xml.Name        `xml:"component"`
		Name           string          `xml:"name,attr"`
		Configurations []Configuration `xml:"configuration"`
	}

	type Project struct {
		XMLName    xml.Name    `xml:"project"`
		Version    int         `xml:"version,attr"`
		Components []Component `xml:"component"`
	}

	var project Project
	err = xml.Unmarshal(data, &project)
	if err != nil {
		log.Ctx(ctx).Debug().
			Err(err).
			Str("file", workspacePath).
			Msg("Cannot unmarshal JetBrains workspace file")
		return findings
	}

	if project.Version != 4 {
		log.Ctx(ctx).Debug().
			Int("project_version", project.Version).
			Msg("Unsupported JetBrains project version, findings may be inaccurate")
	}

	for _, component := range project.Components {
		if component.Name != "RunManager" {
			continue
		}

		for _, configuration := range component.Configurations {
			args := configuration.Parameters.Value
			if strings.TrimSpace(args) != "" {
				detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
					Source:    "file:" + workspacePath,
					ProbeName: p.Name(),
				}).WithExtra("config_name", configuration.Name)
				if line := xmlValueLine(data, args); line > 0 {
					detCtx = detCtx.WithLineNumber(line)
				}
				findings = append(findings, p.detectorRegistry.DetectAll(args, detCtx)...)
			}

			env := configuration.Environment.Variables
			for _, envVar := range env {
				detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
					Source:    "file:" + workspacePath,
					ProbeName: p.Name(),
				}).WithEnvVarName(envVar.Name).WithExtra("config_name", configuration.Name)
				if line := xmlValueLine(data, envVar.Value); line > 0 {
					detCtx = detCtx.WithLineNumber(line)
				}
				findings = append(findings, p.detectorRegistry.DetectAll(envVar.Value, detCtx)...)
			}
		}
	}

	return findings
}

// xmlValueLine returns the 1-based line where value first appears in the raw
// XML source, or 0 if not found. encoding/xml unescapes attribute values on
// unmarshal, so a parsed value containing the original characters '&', '<',
// '>', '"', or '\” won't substring-match the on-disk representation; in
// those cases we omit the line number rather than guess.
func xmlValueLine(content []byte, value string) int {
	if value == "" || strings.ContainsAny(value, "&<>\"'") {
		return 0
	}
	idx := bytes.Index(content, []byte(value))
	if idx < 0 {
		return 0
	}
	return bytes.Count(content[:idx], []byte("\n")) + 1
}
