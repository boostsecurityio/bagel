// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeK8sSAToken builds a JWS whose claims mark it as a Kubernetes
// service account token — same shape the JWT detector classifies.
func makeK8sSAToken(t *testing.T) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body, err := json.Marshal(map[string]any{
		"iss": "https://kubernetes.default.svc.cluster.local",
		"sub": "system:serviceaccount:default:my-sa",
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"serviceaccount": map[string]any{
				"name": "my-sa",
			},
		},
	})
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + ".signature_placeholder_long_enough_to_match"
}

func newKubeRegistry() *detector.Registry {
	reg := detector.NewRegistry()
	reg.Register(detector.NewJWTDetector())
	reg.Register(detector.NewSSHPrivateKeyDetector())
	reg.Register(detector.NewHTTPAuthDetector())
	reg.Register(detector.NewGenericAPIKeyDetector())
	return reg
}

func TestKubeProbe_LineScanCatchesInlineToken(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config")
	token := makeK8sSAToken(t)
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
users:
- name: kube-admin
  user:
    token: %s
`, token)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	index := fileindex.NewFileIndex()
	index.Add("kubeconfig", path)

	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(index)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	var jwt *models.Finding
	for i := range findings {
		if findings[i].ID == "jwt-jwt-token" {
			jwt = &findings[i]
			break
		}
	}
	require.NotNil(t, jwt, "expected JWT finding from kubeconfig token line, got: %+v", findings)
	// Existing JWT contract — ID/Title/token_type stable, subtype carries
	// the K8s classification.
	assert.Equal(t, "JWT Token Detected", jwt.Title)
	assert.Equal(t, "jwt-token", jwt.Metadata["token_type"])
	assert.Equal(t, "jwt-kubernetes-service-account", jwt.Metadata["token_subtype"])
	assert.Equal(t, "default", jwt.Metadata["k8s_namespace"])
	assert.Equal(t, "my-sa", jwt.Metadata["k8s_serviceaccount"])
}

func TestKubeProbe_YAMLDecodesInlineClientKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config")

	// Realistic-looking unencrypted PEM block. The SSH-private-key
	// detector's regex matches any "-----BEGIN ... PRIVATE KEY-----"
	// envelope, so this works as a stand-in for a real EC/RSA key.
	pem := "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ" +
		"DemoFakeKeyMaterialForTestUseOnlyAbsolutelyNotARealKey" +
		"\n-----END PRIVATE KEY-----"
	encodedKey := base64.StdEncoding.EncodeToString([]byte(pem))

	content := fmt.Sprintf(`apiVersion: v1
kind: Config
users:
- name: cert-admin
  user:
    client-key-data: %s
`, encodedKey)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	index := fileindex.NewFileIndex()
	index.Add("kubeconfig", path)

	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(index)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	var pemFinding *models.Finding
	for i := range findings {
		if findings[i].ID == "ssh-private-key-pkcs8" {
			pemFinding = &findings[i]
			break
		}
	}
	require.NotNil(t, pemFinding, "expected PEM finding from decoded client-key-data, got: %+v", findings)
	assert.Equal(t, path, pemFinding.Metadata["kubeconfig_path"])
	assert.Equal(t, "cert-admin", pemFinding.Metadata["kubeconfig_user"])
	assert.Equal(t, "client-key-data", pemFinding.Metadata["kubeconfig_field"])
}

func TestKubeProbe_KUBECONFIGEnvVarHonored(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "extra-config")
	token := makeK8sSAToken(t)
	content := "users:\n- name: env\n  user:\n    token: " + token + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	t.Setenv("KUBECONFIG", path)

	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(fileindex.NewFileIndex()) // no kubeconfig pattern entries

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "KUBECONFIG-pointed file should still be scanned")
}

func TestKubeProbe_DeduplicatesPathsAcrossSources(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config")
	token := makeK8sSAToken(t)
	content := "users:\n- name: dup\n  user:\n    token: " + token + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	index := fileindex.NewFileIndex()
	index.Add("kubeconfig", path)
	t.Setenv("KUBECONFIG", path) // same path via env

	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(index)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	jwtCount := 0
	for _, f := range findings {
		if f.ID == "jwt-jwt-token" {
			jwtCount++
		}
	}
	assert.Equal(t, 1, jwtCount, "same path reached via file index + env must be scanned once")
}

func TestKubeProbe_SkipsOversizedKubeconfig(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "big-config")
	// 16 KB of irrelevant content — well under default cap, but we
	// reduce the cap via flag.
	require.NoError(t, os.WriteFile(path, make([]byte, 16*1024), 0600))

	index := fileindex.NewFileIndex()
	index.Add("kubeconfig", path)

	probe := NewKubeProbe(models.ProbeSettings{
		Enabled: true,
		Flags:   map[string]interface{}{"max_file_size": 1024},
	}, newKubeRegistry())
	probe.SetFileIndex(index)

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestKubeProbe_NoFileIndexAndNoEnvReturnsNothing(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	// Zero out system paths for the duration so the test passes on
	// machines that have /etc/rancher/k3s/k3s.yaml present.
	orig := systemKubeconfigPaths
	t.Cleanup(func() { systemKubeconfigPaths = orig })
	systemKubeconfigPaths = nil

	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestKubeProbe_SystemKubeconfigPathScannedWhenPresent(t *testing.T) {
	// Stand in for /etc/rancher/k3s/k3s.yaml — we redirect the
	// system-path list at a tmp file we can actually write.
	tmpDir := t.TempDir()
	sysPath := filepath.Join(tmpDir, "k3s.yaml")
	token := makeK8sSAToken(t)
	require.NoError(t, os.WriteFile(sysPath, []byte(
		"users:\n- name: admin\n  user:\n    token: "+token+"\n",
	), 0600))

	orig := systemKubeconfigPaths
	t.Cleanup(func() { systemKubeconfigPaths = orig })
	systemKubeconfigPaths = []string{sysPath}

	t.Setenv("KUBECONFIG", "")
	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(fileindex.NewFileIndex()) // no kubeconfig pattern entries

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)

	var jwt *models.Finding
	for i := range findings {
		if findings[i].ID == "jwt-jwt-token" {
			jwt = &findings[i]
		}
	}
	require.NotNil(t, jwt, "system kubeconfig must be stat'd + scanned without a file-index hit")
	assert.Equal(t, "jwt-kubernetes-service-account", jwt.Metadata["token_subtype"])
}

func TestKubeProbe_SystemKubeconfigMissingNoError(t *testing.T) {
	orig := systemKubeconfigPaths
	t.Cleanup(func() { systemKubeconfigPaths = orig })
	systemKubeconfigPaths = []string{"/nonexistent/path/should-not-exist.yaml"}

	t.Setenv("KUBECONFIG", "")
	probe := NewKubeProbe(models.ProbeSettings{Enabled: true}, newKubeRegistry())
	probe.SetFileIndex(fileindex.NewFileIndex())

	findings, err := probe.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}
