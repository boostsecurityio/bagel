// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// DockerCredsProbe checks for Docker registry creds in cleartext
type DockerCredsProbe struct {
	enabled bool
	config  models.ProbeSettings
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

// Execute runs the Docker credentials probe
func (dcp *DockerCredsProbe) Execute(_ context.Context) ([]models.Finding, error) {
	var findings []models.Finding
	locations, err := configLocations()
	if err != nil {
		return findings, err
	}
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

func configLocations() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	locations := []string{
		filepath.Join(home, ".docker", "config.json"),
		filepath.Join(home, ".config", "containers", "auth.json"),
	}
	xdgDir, found := os.LookupEnv("XDG_RUNTIME_DIR")
	if found {
		locations = append(locations, filepath.Join(xdgDir, "containers", "auth.json"))
	}
	return locations, nil
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
