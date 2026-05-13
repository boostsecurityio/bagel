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

func newIaCRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	// The registry the probe shares with the rest of the scan — the
	// IaC line-scan paths rely on existing detectors firing on
	// embedded values.
	reg.Register(detector.NewGitHubPATDetector())
	reg.Register(detector.NewCloudCredentialsDetector())
	reg.Register(detector.NewJWTDetector())
	reg.Register(detector.NewDatabaseConnectionDetector())
	reg.Register(detector.NewGenericAPIKeyDetector())
	return reg
}

func TestIaCProbe_TerraformCredentialsJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "credentials.tfrc.json")
	require.NoError(t, os.WriteFile(path, []byte(`{
  "credentials": {
    "app.terraform.io": {"token": "atlas.v1.aaaabbbbccccddddeeeeffffgggghhhh"},
    "tfe.example.com":  {"token": "atlas.v1.shouldnotmatterforthetest"}
  }
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_credentials", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 2)

	hosts := make(map[string]bool)
	for _, f := range findings {
		assert.Equal(t, "terraform-cloud-credential", f.ID)
		assert.Equal(t, "critical", f.Severity)
		assert.Equal(t, "json", f.Metadata["file_format"])
		assert.Equal(t, "atlas.v1", f.Metadata["token_prefix"])
		hosts[f.Metadata["host"].(string)] = true
	}
	assert.True(t, hosts["app.terraform.io"])
	assert.True(t, hosts["tfe.example.com"])
}

func TestIaCProbe_TerraformrcHCLFallback(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, ".terraformrc")
	require.NoError(t, os.WriteFile(path, []byte(`
credentials "app.terraform.io" {
  token = "atlas.v1.legacyhclformat0123456789abcdef"
}
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_credentials", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "terraform-cloud-credential", findings[0].ID)
	assert.Equal(t, "hcl", findings[0].Metadata["file_format"])
	assert.Equal(t, "app.terraform.io", findings[0].Metadata["host"])
}

func TestIaCProbe_TfvarsLineScanCatchesCloudCreds(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prod.tfvars")
	// Embed an AWS access key — the existing CloudCredentials detector
	// should fire on this through the line-scan.
	require.NoError(t, os.WriteFile(path, []byte(`
aws_region            = "us-east-1"
aws_access_key_id     = "AKIAIOSFODNN7EXAMPLE"
db_password           = "supersecret"
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_vars", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	awsFound := false
	for _, f := range findings {
		if f.ID == "cloud-credential-aws-access-key-id" {
			awsFound = true
			break
		}
	}
	assert.True(t, awsFound, "expected AWS access key finding from tfvars line scan")
}

func TestIaCProbe_TfstateLineScanCatchesGitHubPAT(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "terraform.tfstate")
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345"
	require.NoError(t, os.WriteFile(path, []byte(`{
  "outputs": {
    "deploy_token": {"value": "`+pat+`"}
  }
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_state", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	found := false
	for _, f := range findings {
		if cls, _ := f.Metadata["token_type"].(string); cls == "classic-pat" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected GitHub PAT finding from tfstate line scan")
}

func TestIaCProbe_HelmRepositoriesWithPassword(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "repositories.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
apiVersion: ""
repositories:
- name: bitnami
  url: https://charts.bitnami.com/bitnami
- name: private-charts
  url: https://charts.example.com
  username: deploy-bot
  password: hunter2-supersecret
- name: another-public
  url: https://other.example.com
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("helm_repositories", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "helm-repository-credential", f.ID)
	assert.Equal(t, "critical", f.Severity)
	assert.Equal(t, "private-charts", f.Metadata["repo_name"])
	assert.Equal(t, "deploy-bot", f.Metadata["username"])
	assert.Equal(t, true, f.Metadata["username_present"])
}

func TestIaCProbe_HelmRepositoriesNoPasswordIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "repositories.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
repositories:
- name: bitnami
  url: https://charts.bitnami.com/bitnami
`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("helm_repositories", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "repos without passwords must not emit findings")
}

func TestIaCProbe_SkipsOversized(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "prod.tfvars")
	require.NoError(t, os.WriteFile(path, make([]byte, 2048), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_vars", path)

	probe := NewIaCProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestIaCProbe_MalformedJSONFallsBackToHCL(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, ".terraformrc")
	// Not JSON; the HCL regex should still produce a finding.
	require.NoError(t, os.WriteFile(path, []byte(`credentials "tfe.local" {
  token = "atlas.v1.0123456789abcdef0123456789abcdef"
}`), 0600))

	idx := fileindex.NewFileIndex()
	idx.Add("terraform_credentials", path)

	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "hcl", findings[0].Metadata["file_format"])
}

func TestIaCProbe_NoFileIndexReturnsNothing(t *testing.T) {
	probe := NewIaCProbe(models.ProbeSettings{Enabled: true}, newIaCRegistry())
	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}
