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

func TestWireGuardProbe_Execute(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a WireGuard config with a private key
	confPath := filepath.Join(tmpDir, "wg0.conf")
	confContent := `[Interface]
Address = 10.0.0.1/24
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0`
	err := os.WriteFile(confPath, []byte(confContent), 0600)
	require.NoError(t, err)

	index := fileindex.NewFileIndex()
	index.Add("wireguard_config", confPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewWireGuardKeyDetector())

	probe := NewWireGuardProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "wireguard-private-key", findings[0].ID)
	assert.Equal(t, "critical", findings[0].Severity)
}

func TestWireGuardProbe_ExecuteNoPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Config without a private key (peer-only config)
	confPath := filepath.Join(tmpDir, "wg0.conf")
	confContent := `[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.0.0.0/24`
	err := os.WriteFile(confPath, []byte(confContent), 0600)
	require.NoError(t, err)

	index := fileindex.NewFileIndex()
	index.Add("wireguard_config", confPath)

	registry := detector.NewRegistry()
	registry.Register(detector.NewWireGuardKeyDetector())

	probe := NewWireGuardProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWireGuardProbe_ExecuteWithoutFileIndex(t *testing.T) {
	registry := detector.NewRegistry()
	registry.Register(detector.NewWireGuardKeyDetector())

	probe := NewWireGuardProbe(models.ProbeSettings{Enabled: true}, registry)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	// May return empty (no system-level WireGuard configs expected in CI)
	_ = findings
}

func TestWireGuardProbe_FileReadError(t *testing.T) {
	index := fileindex.NewFileIndex()
	index.Add("wireguard_config", "/path/to/nonexistent/wg0.conf")

	registry := detector.NewRegistry()
	registry.Register(detector.NewWireGuardKeyDetector())

	probe := NewWireGuardProbe(models.ProbeSettings{Enabled: true}, registry)
	probe.SetFileIndex(index)

	ctx := context.Background()
	findings, err := probe.Execute(ctx)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestWireGuardProbe_Name(t *testing.T) {
	registry := detector.NewRegistry()
	probe := NewWireGuardProbe(models.ProbeSettings{Enabled: true}, registry)
	assert.Equal(t, "wireguard", probe.Name())
}

func TestWireGuardProbe_IsEnabled(t *testing.T) {
	registry := detector.NewRegistry()

	tests := []struct {
		name    string
		enabled bool
	}{
		{"Probe enabled", true},
		{"Probe disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := NewWireGuardProbe(models.ProbeSettings{Enabled: tt.enabled}, registry)
			assert.Equal(t, tt.enabled, probe.IsEnabled())
		})
	}
}
