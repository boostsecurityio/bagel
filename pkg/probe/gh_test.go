// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os/exec"
	"runtime"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGHProbe_Name(t *testing.T) {
	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	assert.Equal(t, "gh", probe.Name())
}

func TestGHProbe_IsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    bool
	}{
		{
			name:    "Probe enabled",
			enabled: true,
			want:    true,
		},
		{
			name:    "Probe disabled",
			enabled: false,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := NewGHProbe(models.ProbeSettings{Enabled: tt.enabled}, detector.NewRegistry())
			assert.Equal(t, tt.want, probe.IsEnabled())
		})
	}
}

func TestGHProbe_Execute_GHNotInstalled(t *testing.T) {
	// Set PATH to a nonexistent directory so gh won't be found
	// t.Setenv automatically restores the original value after the test
	t.Setenv("PATH", "/nonexistent")

	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	findings, err := probe.Execute(context.Background())

	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings when gh is not installed")
}

func TestGHProbe_Execute_Integration(t *testing.T) {
	// Skip if gh is not installed
	_, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("gh CLI not installed, skipping integration test")
	}

	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	findings, err := probe.Execute(context.Background())

	require.NoError(t, err)

	// The result depends on whether gh is authenticated
	// If authenticated: 1 finding
	// If not authenticated: 0 findings
	// Either is acceptable - we just verify the probe runs without error
	if len(findings) > 0 {
		assert.Equal(t, "gh-auth-token-present", findings[0].ID)
		assert.Equal(t, "medium", findings[0].Severity)
		assert.Equal(t, "gh", findings[0].Probe)
		assert.Equal(t, "GitHub CLI Authentication Detected", findings[0].Title)
		assert.NotEmpty(t, findings[0].Path)
		assert.NotEmpty(t, findings[0].Message)
	}
}

func TestGHProbe_Execute_ContextCancellation(t *testing.T) {
	// Skip if gh is not installed
	_, err := exec.LookPath("gh")
	if err != nil {
		t.Skip("gh CLI not installed, skipping context cancellation test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	findings, err := probe.Execute(ctx)

	// With a cancelled context, the command should fail and return no findings
	require.NoError(t, err)
	assert.Empty(t, findings, "Should return no findings when context is cancelled")
}

func TestGHProbe_CheckKeychainLeftover_NoCredential(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, registry)
	findings := probe.checkKeychainLeftover(context.Background(), false)

	// We can't assert the exact result since it depends on keychain state,
	// but the method should not panic or return an error
	_ = findings
}

func TestGHProbe_CheckKeychainLeftover_SkipsWhenAuthenticated(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}

	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())

	probe := NewGHProbe(models.ProbeSettings{Enabled: true}, registry)
	// When gh is authenticated, leftover keychain creds are expected -- no finding
	findings := probe.checkKeychainLeftover(context.Background(), true)
	assert.Empty(t, findings, "Should not report keychain credential when gh is authenticated")
}
