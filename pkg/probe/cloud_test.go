// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudProbe_Name(t *testing.T) {
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	probe := NewCloudProbe(config, registry)

	assert.Equal(t, "cloud", probe.Name())
}

func TestCloudProbe_IsEnabled(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		expected bool
	}{
		{
			name:     "Enabled",
			enabled:  true,
			expected: true,
		},
		{
			name:     "Disabled",
			enabled:  false,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := models.ProbeSettings{Enabled: tt.enabled}
			registry := detector.NewRegistry()
			probe := NewCloudProbe(config, registry)

			assert.Equal(t, tt.expected, probe.IsEnabled())
		})
	}
}

func TestCloudProbe_AWS_Credentials(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	err := os.MkdirAll(awsDir, 0755)
	require.NoError(t, err)

	// Create AWS credentials file with test credentials
	credentialsFile := filepath.Join(awsDir, "credentials")
	credentialsContent := `[default]
aws_access_key_id = AKIAIOSFODNNEXAMPLE2
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`
	err = os.WriteFile(credentialsFile, []byte(credentialsContent), 0600)
	require.NoError(t, err)

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("aws_credentials", credentialsFile)

	// Create probe with cloud credentials detector
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	probe := NewCloudProbe(config, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	// Verify
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 1, "Should detect AWS secret key")

	// Check that findings have correct metadata
	foundAccessKeyID := false

	for _, finding := range findings {
		assert.Equal(t, "cloud", finding.Probe)
		assert.Equal(t, "file:"+credentialsFile, finding.Path)

		tokenType := finding.Metadata["token_type"]
		if tokenType == "aws-access-key-id" {
			foundAccessKeyID = true
			assert.Equal(t, "critical", finding.Severity)
		}
	}

	assert.True(t, foundAccessKeyID, "Should detect AWS Access Key ID")
}

func TestCloudProbe_GCP_Credentials(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()
	gcpDir := filepath.Join(tmpDir, ".config", "gcloud")
	err := os.MkdirAll(gcpDir, 0755)
	require.NoError(t, err)

	// Create GCP config file with API key
	credentialsFile := filepath.Join(gcpDir, "properties")
	credentialsContent := `[core]
api_key = AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe
project = my-project-123
`
	err = os.WriteFile(credentialsFile, []byte(credentialsContent), 0600)
	require.NoError(t, err)

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("gcp_config", credentialsFile)

	// Create probe with cloud credentials detector
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	probe := NewCloudProbe(config, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	// Verify - should find the GCP API key
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 1, "Should detect GCP API key")

	// Check that findings have correct metadata
	for _, finding := range findings {
		assert.Equal(t, "cloud", finding.Probe)
		assert.Equal(t, "file:"+credentialsFile, finding.Path)
		assert.Equal(t, "critical", finding.Severity)
		assert.Equal(t, "gcp-api-key", finding.Metadata["token_type"])
	}
}

func TestCloudProbe_MultipleProviders(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Create AWS credentials
	awsDir := filepath.Join(tmpDir, ".aws")
	err := os.MkdirAll(awsDir, 0755)
	require.NoError(t, err)

	awsFile := filepath.Join(awsDir, "credentials")
	awsContent := `[default]
aws_access_key_id = AKIAIEXAMPLEKEY2TEST
aws_secret_access_key = Je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
`
	err = os.WriteFile(awsFile, []byte(awsContent), 0600)
	require.NoError(t, err)

	// Create GCP config with API key
	gcpDir := filepath.Join(tmpDir, ".config", "gcloud")
	err = os.MkdirAll(gcpDir, 0755)
	require.NoError(t, err)

	gcpFile := filepath.Join(gcpDir, "properties")
	gcpContent := `[core]
api_key = AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe
project = my-project-123
`
	err = os.WriteFile(gcpFile, []byte(gcpContent), 0600)
	require.NoError(t, err)

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("aws_credentials", awsFile)
	index.Add("gcp_config", gcpFile)

	// Create probe with cloud credentials detector
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	probe := NewCloudProbe(config, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	// Verify
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 2, "Should detect credentials from both providers")

	// Count findings by provider
	awsCount := 0
	gcpCount := 0

	for _, finding := range findings {
		assert.Equal(t, "cloud", finding.Probe)

		tokenType := finding.Metadata["token_type"].(string)
		if len(tokenType) >= 3 && tokenType[:3] == "aws" {
			awsCount++
		} else if len(tokenType) >= 3 && tokenType[:3] == "gcp" {
			gcpCount++
		}
	}

	assert.GreaterOrEqual(t, awsCount, 1, "Should detect AWS Access Key ID")
	assert.GreaterOrEqual(t, gcpCount, 1, "Should detect GCP API key")
}

func TestCloudProbe_NoFileIndex(t *testing.T) {
	// Create probe without file index
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	probe := NewCloudProbe(config, registry)

	// Execute probe (should handle gracefully)
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	// Verify
	require.NoError(t, err)
	assert.Empty(t, findings, "Should return empty findings when file index not available")
}

func TestCloudProbe_MultipleDetectors(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	err := os.MkdirAll(awsDir, 0755)
	require.NoError(t, err)

	// Create AWS credentials file with:
	// - AWS Access Key ID (detected by CloudCredentialsDetector)
	// - GitHub PAT (detected by GitHubPATDetector)
	// - Generic high-entropy key (detected by GenericAPIKeyDetector)
	credentialsFile := filepath.Join(awsDir, "credentials")
	credentialsContent := `[default]
aws_access_key_id = AKIAIOSFODNNEXAMPLE2

# GitHub token for CI/CD
github_token = ghp_1234567890123456789012345678901234567890

# Some other API key
api_key = 9dj2K8sL4mP7nQ3rT6vW1xY5zA
`
	err = os.WriteFile(credentialsFile, []byte(credentialsContent), 0600)
	require.NoError(t, err)

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("aws_credentials", credentialsFile)

	// Create probe with multiple detectors
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewGenericAPIKeyDetector())
	probe := NewCloudProbe(config, registry)
	probe.SetFileIndex(index)

	// Execute probe
	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	// Verify
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 3, "Should detect secrets from multiple detectors")

	// Check that findings from different detectors are present
	foundAWSAccessKeyID := false
	foundGitHubPAT := false
	foundGenericKey := false

	for _, finding := range findings {
		assert.Equal(t, "cloud", finding.Probe)
		assert.Equal(t, "file:"+credentialsFile, finding.Path)

		switch finding.ID {
		case "cloud-credential-aws-access-key-id":
			foundAWSAccessKeyID = true
		case "github-token-classic-pat":
			foundGitHubPAT = true
		case "generic-api-key":
			foundGenericKey = true
		}
	}

	assert.True(t, foundAWSAccessKeyID, "Should detect AWS Access Key ID with CloudCredentialsDetector")
	assert.True(t, foundGitHubPAT, "Should detect GitHub PAT with GitHubPATDetector")
	assert.True(t, foundGenericKey, "Should detect generic key with GenericAPIKeyDetector")
}

func TestCloudProbe_UnreadableFile(t *testing.T) {
	// Create temp directory for test files
	tmpDir := t.TempDir()
	awsDir := filepath.Join(tmpDir, ".aws")
	err := os.MkdirAll(awsDir, 0755)
	require.NoError(t, err)

	// Create a file that we'll make unreadable
	credentialsFile := filepath.Join(awsDir, "credentials")
	err = os.WriteFile(credentialsFile, []byte("test"), 0600)
	require.NoError(t, err)

	// Make file unreadable (this may not work on all systems)
	err = os.Chmod(credentialsFile, 0000)
	require.NoError(t, err)

	// Restore permissions after test
	defer func() {
		_ = os.Chmod(credentialsFile, 0600)
	}()

	// Create file index
	index := fileindex.NewFileIndex()
	index.Add("aws_credentials", credentialsFile)

	// Create probe
	config := models.ProbeSettings{Enabled: true}
	registry := detector.NewRegistry()
	registry.Register(detector.NewCloudCredentialsDetector())
	probe := NewCloudProbe(config, registry)
	probe.SetFileIndex(index)

	// Execute probe (should handle gracefully)
	ctx := context.Background()
	_, err = probe.Execute(ctx)

	// Verify - should not error, just log and continue
	require.NoError(t, err)
	// Note: depending on permissions, we might get findings or not
	// The key is that it doesn't crash
}
