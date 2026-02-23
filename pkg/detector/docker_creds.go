// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"encoding/json"
	"fmt"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// DockerCredentialsDetector detects cleartext secrets in Docker config files
type DockerCredentialsDetector struct{}

func NewDockerCredentialsDetector() *DockerCredentialsDetector {
	return &DockerCredentialsDetector{}
}

// Name returns the detector name
func (dcd *DockerCredentialsDetector) Name() string {
	return "docker-credentials"
}

// Detect scans content for Docker credentials and returns findings
func (dcd *DockerCredentialsDetector) Detect(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding
	regsWithCreds, err := regsWithCreds(content)
	if err != nil {
		return findings
	}
	for _, registry := range regsWithCreds {
		findings = append(findings, dcd.createFinding(ctx.Source, registry))
	}
	return findings
}

// createFinding creates a finding for a detected Docker cred
func (dcd *DockerCredentialsDetector) createFinding(location string, registry string) models.Finding {
	return models.Finding{
		ID:       fmt.Sprintf("%-%s", dcd.Name(), registry),
		Probe:    dcd.Name(),
		Title:    "Docker credentials found",
		Message:  fmt.Sprintf("%s contains cleartext credentials for %s. Consider using a credential helper.", location, registry),
		Path:     location,
		Severity: "high",
	}
}

func regsWithCreds(fileContents string) ([]string, error) {
	var registries []string
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(fileContents), &config); err != nil {
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
