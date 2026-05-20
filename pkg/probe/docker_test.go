// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDockerRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	reg.Register(detector.NewGitHubPATDetector())
	reg.Register(detector.NewJWTDetector())
	return reg
}

func writeDockerConfig(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))
	return path
}

func TestDockerProbe_DetectsInlineBasicAuth(t *testing.T) {
	tmpDir := t.TempDir()
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:hunter2"))
	path := writeDockerConfig(t, tmpDir, `{
  "auths": {
    "ghcr.io": {"auth": "`+encoded+`"}
  },
  "credsStore": "osxkeychain"
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("docker_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "docker-registry-inline-auth", f.ID)
	assert.Equal(t, "critical", f.Severity)
	assert.Equal(t, "docker", f.Metadata["runtime"])
	assert.Equal(t, "ghcr.io", f.Metadata["registry_host"])
	assert.Equal(t, "alice", f.Metadata["username"])
	assert.Equal(t, true, f.Metadata["has_password"])
}

func TestDockerProbe_PasswordWhichIsGitHubPAT_AlsoSurfacesPATFinding(t *testing.T) {
	tmpDir := t.TempDir()
	// User stashed a real PAT as the registry password. The decoded
	// password should flow through the registry and surface as a
	// classic PAT finding alongside the docker finding.
	pat := "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345" // 36 chars after prefix
	encoded := base64.StdEncoding.EncodeToString([]byte("bot:" + pat))
	path := writeDockerConfig(t, tmpDir, `{"auths":{"ghcr.io":{"auth":"`+encoded+`"}}}`)

	idx := fileindex.NewFileIndex()
	idx.Add("docker_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.ID] = true
	}
	assert.True(t, ids["docker-registry-inline-auth"], "missing docker finding")
	// GitHub PAT detector's finding ID for classic PAT is the same as
	// the detector's prefix — check by membership.
	hasPATFinding := false
	for _, f := range findings {
		if f.Metadata["token_type"] == "classic-pat" {
			hasPATFinding = true
			assert.Equal(t, "ghcr.io", f.Metadata["registry_host"])
			break
		}
	}
	assert.True(t, hasPATFinding, "expected GitHub PAT finding from decoded password")
}

func TestDockerProbe_EmptyAuthIgnored(t *testing.T) {
	tmpDir := t.TempDir()
	// Real-world shape when a credential helper is used — auths entry
	// present but auth field empty.
	path := writeDockerConfig(t, tmpDir, `{
  "auths": {"ghcr.io": {}},
  "credsStore": "osxkeychain"
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("docker_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "credential-helper-only config must not emit findings")
}

func TestDockerProbe_DetectsIdentityToken(t *testing.T) {
	tmpDir := t.TempDir()
	path := writeDockerConfig(t, tmpDir, `{
  "auths": {
    "myregistry.azurecr.io": {"identitytoken": "some-azure-acr-refresh-token"}
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("docker_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	assert.Equal(t, "docker-registry-inline-identity-token", findings[0].ID)
	assert.Equal(t, "myregistry.azurecr.io", findings[0].Metadata["registry_host"])
}

func TestDockerProbe_HandlesPodmanAuthFile(t *testing.T) {
	tmpDir := t.TempDir()
	encoded := base64.StdEncoding.EncodeToString([]byte("user:pw"))
	path := writeDockerConfig(t, tmpDir, `{"auths":{"quay.io":{"auth":"`+encoded+`"}}}`)

	idx := fileindex.NewFileIndex()
	idx.Add("podman_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "podman", findings[0].Metadata["runtime"])
}

func TestDockerProbe_MalformedJSONReturnsNoError(t *testing.T) {
	tmpDir := t.TempDir()
	path := writeDockerConfig(t, tmpDir, `{not json`)

	idx := fileindex.NewFileIndex()
	idx.Add("docker_config", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDockerProbe_DisabledByConfig(t *testing.T) {
	probe := NewDockerProbe(models.ProbeSettings{Enabled: false}, newDockerRegistry())
	assert.False(t, probe.IsEnabled())
}

func TestDockerProbe_HelmOCIRegistry_InlineAuth(t *testing.T) {
	// Helm's OCI registry config uses the same JSON shape as Docker's
	// config.json — the existing auths parser handles it; this test
	// confirms the helm_oci_registry pattern is wired into the probe's
	// source list and that the runtime metadata is `helm`.
	tmpDir := t.TempDir()
	encoded := base64.StdEncoding.EncodeToString([]byte("helmbot:hunter2"))
	path := writeDockerConfig(t, tmpDir, `{
  "auths": {
    "registry.example.com": {"auth": "`+encoded+`"}
  }
}`)

	idx := fileindex.NewFileIndex()
	idx.Add("helm_oci_registry", path)

	probe := NewDockerProbe(models.ProbeSettings{Enabled: true}, newDockerRegistry())
	probe.SetFileIndex(idx)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "docker-registry-inline-auth", f.ID)
	assert.Equal(t, "helm", f.Metadata["runtime"])
	assert.Equal(t, "registry.example.com", f.Metadata["registry_host"])
	assert.Equal(t, "helmbot", f.Metadata["username"])
}
