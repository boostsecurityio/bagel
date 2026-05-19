// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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

// Phase D-1: cloud / SaaS CLI round-up. The probe consumes a single
// shared pattern slice (cloudCredentialPatterns); these tests lock
// in the slice membership by inserting one credential-bearing file
// per vendor pattern and asserting the registry picks it up.

func newD1Registry() *detector.Registry {
	r := detector.NewRegistry()
	r.Register(detector.NewCloudCredentialsDetector())
	r.Register(detector.NewJWTDetector())
	r.Register(detector.NewGitHubPATDetector())
	r.Register(detector.NewGenericAPIKeyDetector())
	return r
}

func TestCloudProbe_AWS_SSO_Cache(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "11aabbccdd.json")
	// Realistic SSO cache shape: accessToken is the secret, the rest is metadata.
	require.NoError(t, os.WriteFile(path, []byte(`{
"startUrl":"https://example.awsapps.com/start",
"accessToken":"aoatJ.veryLongSSOAccessTokenWithEnoughCharsToHitGenericKeyDetector",
"expiresAt":"2099-01-01T00:00:00Z"
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_sso_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings, "SSO cache accessToken must be picked up by the registry")
}

func TestCloudProbe_Azure_Tokens(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "accessTokens.json")
	// Single-line JWT in a JSON value — JWT detector must fire.
	pat := "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hYWFhYWFhYS1hYWFhLWFhYWEtYWFhYS1hYWFhYWFhYWFhYWEvIn0.signaturepartlongenoughtomatch"
	require.NoError(t, os.WriteFile(path, []byte(`[{"accessToken":"`+pat+`"}]`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("azure_tokens", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	// JWT subtype enrichment should classify it as Azure AD.
	hasAzure := false
	for _, f := range findings {
		if f.Metadata["token_subtype"] == "jwt-azure-ad" {
			hasAzure = true
		}
	}
	assert.True(t, hasAzure, "Azure AD JWT subtype must be set on the finding")
}

func TestCloudProbe_VendorCLIs_AllPatternsHit(t *testing.T) {
	tmpDir := t.TempDir()
	// One credential-bearing file per single-vendor pattern. Body uses
	// an AWS-shaped access key — the most universally-recognized secret
	// shape — so we don't depend on per-vendor detectors that don't
	// exist yet. The point is that the file is reached and scanned.
	akia := "AKIAIOSFODNN7EXAMPLE"
	cases := []struct {
		pattern string
		body    string
	}{
		{"oci_config", "[DEFAULT]\nkey=" + akia + "\n"},
		{"aliyun_config", `{"profiles":[{"access_key_id":"` + akia + `"}]}`},
		{"bluemix_config", `{"IAMToken":"` + akia + `"}`},
		{"doctl_config", "access-token: " + akia + "\n"},
		{"hcloud_config", "token = \"" + akia + "\"\n"},
		{"scw_config", "secret_key: " + akia + "\n"},
		{"linode_config", "token=" + akia + "\n"},
		{"fly_config", "access_token: " + akia + "\n"},
		{"vercel_config", `{"token":"` + akia + `"}`},
		{"railway_config", `{"token":"` + akia + `"}`},
		{"snowflake_config", "password = \"" + akia + "\"\n"},
		{"doppler_config", "token: " + akia + "\n"},
	}

	idx := fileindex.NewFileIndex()
	for i, c := range cases {
		path := filepath.Join(tmpDir, c.pattern+strconv.Itoa(i))
		require.NoError(t, os.WriteFile(path, []byte(c.body), 0600))
		idx.Add(c.pattern, path)
	}

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	hit := 0
	for _, f := range findings {
		if f.ID == "cloud-credential-aws-access-key-id" {
			hit++
		}
	}
	assert.Equal(t, len(cases), hit,
		"each vendor pattern must produce at least one cloud-credential finding (got %d of %d)",
		hit, len(cases))
}

// Expired AWS SSO / CLI cache files are the dominant source of false
// positives for those two patterns — the files sit on disk long after
// the embedded credential is dead. The probe pre-checks expiry and
// skips dead files entirely; these tests lock that behavior in.

func TestCloudProbe_AWS_CLI_Cache_Expired_Skipped(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "expired.json")
	// 16 months ago — well past any reasonable session lifetime.
	require.NoError(t, os.WriteFile(path, []byte(`{
"Credentials": {
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "SessionToken": "IQoJb3JpZ2luX2VjStillExampleNoLongerValid",
  "Expiration": "2025-01-21T09:42:24Z"
}}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_cli_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "expired CLI cache must not produce findings")
}

func TestCloudProbe_AWS_CLI_Cache_Fresh_Reported(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "fresh.json")
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	require.NoError(t, os.WriteFile(path, []byte(`{
"Credentials": {
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Expiration": "`+future+`"
}}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_cli_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "live CLI cache must be reported")
}

func TestCloudProbe_AWS_SSO_Cache_Expired_Skipped(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sso-expired.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
"startUrl":"https://example.awsapps.com/start",
"accessToken":"aoatJ.veryLongSSOAccessTokenWithEnoughCharsToHitGenericKeyDetector",
"expiresAt":"2025-01-01T00:00:00Z"
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_sso_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "expired SSO cache must not produce findings")
}

func TestCloudProbe_AWS_SSO_Cache_Fresh_Reported(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "sso-fresh.json")
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	require.NoError(t, os.WriteFile(path, []byte(`{
"startUrl":"https://example.awsapps.com/start",
"accessToken":"aoatJ.veryLongSSOAccessTokenWithEnoughCharsToHitGenericKeyDetector",
"expiresAt":"`+future+`"
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_sso_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "live SSO cache must be reported")
}

func TestCloudProbe_AWS_Cache_MalformedFile_StillScanned(t *testing.T) {
	// When we can't tell whether the cache is expired (bad JSON, missing
	// expiry field, etc.) we err toward reporting — better a noisy
	// finding the user can dismiss than silently dropping a live token.
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "malformed.json")
	require.NoError(t, os.WriteFile(path,
		[]byte(`AccessKeyId=AKIAIOSFODNN7EXAMPLE`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_cli_cache", path)

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "malformed cache file must still be scanned")
}

func TestCloudProbe_DeduplicatesPathsAcrossPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "shared")
	require.NoError(t, os.WriteFile(path, []byte("key=AKIAIOSFODNN7EXAMPLE\n"), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("aws_credentials", path)
	idx.Add("oci_config", path) // same path under two patterns

	probe := NewCloudProbe(models.ProbeSettings{Enabled: true}, newD1Registry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	hit := 0
	for _, f := range findings {
		if f.ID == "cloud-credential-aws-access-key-id" {
			hit++
		}
	}
	assert.Equal(t, 1, hit, "same path indexed under multiple patterns must be scanned once")
}
