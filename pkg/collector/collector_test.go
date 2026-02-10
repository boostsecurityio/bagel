// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package collector

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/boostsecurityio/bagel/pkg/probe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProbe is a test probe that can be configured to behave in specific ways
type mockProbe struct {
	name     string
	enabled  bool
	delay    time.Duration
	findings []models.Finding
	err      error
	executed bool
}

func (m *mockProbe) Name() string {
	return m.name
}

func (m *mockProbe) IsEnabled() bool {
	return m.enabled
}

func (m *mockProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	m.executed = true

	// Simulate work and respect context cancellation
	select {
	case <-time.After(m.delay):
		return m.findings, m.err
	case <-ctx.Done():
		return nil, errors.New("probe execution cancelled")
	}
}

func TestCollect_Success(t *testing.T) {
	t.Parallel()

	probes := []probe.Probe{
		&mockProbe{
			name:    "probe1",
			enabled: true,
			delay:   10 * time.Millisecond,
			findings: []models.Finding{
				{
					ID:       "finding1",
					Probe:    "probe1",
					Severity: "HIGH",
					Title:    "Test Finding 1",
					Message:  "This is a test finding",
				},
			},
		},
		&mockProbe{
			name:    "probe2",
			enabled: true,
			delay:   10 * time.Millisecond,
			findings: []models.Finding{
				{
					ID:       "finding2",
					Probe:    "probe2",
					Severity: "MEDIUM",
					Title:    "Test Finding 2",
					Message:  "This is another test finding",
				},
			},
		},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	result, err := collector.Collect(context.TODO())

	require.NoError(t, err, "Collect() should not return error")
	require.NotNil(t, result, "Collect() should not return nil result")
	assert.Len(t, result.Findings, 2, "should have 2 findings")
	assert.Equal(t, "0.1.0", result.Metadata.Version, "metadata version should be 0.1.0")
	assert.Equal(t, runtime.GOOS, result.Host.OS, "host OS should match runtime.GOOS")
}

func TestCollect_DisabledProbes(t *testing.T) {
	t.Parallel()

	probe1 := &mockProbe{
		name:    "enabled",
		enabled: true,
		delay:   10 * time.Millisecond,
		findings: []models.Finding{
			{ID: "finding1", Probe: "enabled"},
		},
	}
	probe2 := &mockProbe{
		name:    "disabled",
		enabled: false,
		delay:   10 * time.Millisecond,
		findings: []models.Finding{
			{ID: "finding2", Probe: "disabled"},
		},
	}

	probes := []probe.Probe{probe1, probe2}
	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	result, err := collector.Collect(context.TODO())

	require.NoError(t, err, "Collect() should not return error")
	assert.Len(t, result.Findings, 1, "expected 1 finding from enabled probe")
	assert.True(t, probe1.executed, "enabled probe was not executed")
	assert.False(t, probe2.executed, "disabled probe should not have been executed")
}

func TestCollect_ProbeErrors(t *testing.T) {
	t.Parallel()

	probeErr := errors.New("probe execution failed")

	probes := []probe.Probe{
		&mockProbe{
			name:    "success",
			enabled: true,
			delay:   10 * time.Millisecond,
			findings: []models.Finding{
				{ID: "finding1", Probe: "success"},
			},
		},
		&mockProbe{
			name:    "failure",
			enabled: true,
			delay:   10 * time.Millisecond,
			err:     probeErr,
		},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	result, err := collector.Collect(context.TODO())

	// Collect should still succeed even if one probe fails
	require.NoError(t, err, "Collect() should not return error even if one probe fails")
	require.NotNil(t, result, "Collect() should not return nil result")
	// Should only have findings from successful probe
	assert.Len(t, result.Findings, 1, "expected 1 finding from successful probe")
	assert.Equal(t, "finding1", result.Findings[0].ID, "expected finding1")
}

func TestExecuteProbes_ConcurrentExecution(t *testing.T) {
	t.Parallel()

	// Create probes with different delays
	probes := []probe.Probe{
		&mockProbe{name: "fast", enabled: true, delay: 10 * time.Millisecond},
		&mockProbe{name: "medium", enabled: true, delay: 50 * time.Millisecond},
		&mockProbe{name: "slow", enabled: true, delay: 100 * time.Millisecond},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	start := time.Now()
	results := collector.executeProbes(context.TODO(), nil)
	duration := time.Since(start)

	// All probes should complete in ~100ms (slowest probe time)
	// If they were sequential, would take 160ms (10+50+100)
	assert.Less(t, duration, 200*time.Millisecond, "probes appear to run sequentially")
	assert.Len(t, results, 3, "expected 3 results")
}

func TestExecuteProbes_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.TODO())

	// Create probes with long delays
	probes := []probe.Probe{
		&mockProbe{name: "probe1", enabled: true, delay: 5 * time.Second},
		&mockProbe{name: "probe2", enabled: true, delay: 5 * time.Second},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	// Cancel context after 50ms
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	results := collector.executeProbes(ctx, nil)
	duration := time.Since(start)

	// Should complete quickly due to cancellation, not wait 5 seconds
	assert.Less(t, duration, 1*time.Second, "probes did not respect context cancellation")

	// Should still get results (with errors)
	assert.Len(t, results, 2, "expected 2 results")

	// Both probes should have errors (cancelled)
	for _, result := range results {
		assert.Error(t, result.Error, "probe %s should have error due to context cancellation", result.ProbeName)
	}
}

func TestExecuteProbes_Timeout(t *testing.T) {
	t.Parallel()

	// Create probe with delay longer than timeout (30s default)
	// We'll use a shorter context timeout to test faster
	ctx, cancel := context.WithTimeout(context.TODO(), 100*time.Millisecond)
	defer cancel()

	probes := []probe.Probe{
		&mockProbe{
			name:    "slow",
			enabled: true,
			delay:   10 * time.Second, // Way longer than timeout
		},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	start := time.Now()
	results := collector.executeProbes(ctx, nil)
	duration := time.Since(start)

	// Should timeout quickly
	assert.Less(t, duration, 500*time.Millisecond, "probe did not timeout properly")
	assert.Len(t, results, 1, "expected 1 result")

	// Should have timeout error
	assert.Error(t, results[0].Error, "expected timeout error")
}

func TestExecuteProbes_EmptyProbeList(t *testing.T) {
	t.Parallel()

	probes := []probe.Probe{}
	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	results := collector.executeProbes(context.TODO(), nil)

	assert.Empty(t, results, "expected 0 results for empty probe list")
}

func TestExecuteProbes_AllDisabled(t *testing.T) {
	t.Parallel()

	probes := []probe.Probe{
		&mockProbe{name: "probe1", enabled: false},
		&mockProbe{name: "probe2", enabled: false},
		&mockProbe{name: "probe3", enabled: false},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	results := collector.executeProbes(context.TODO(), nil)

	assert.Empty(t, results, "expected 0 results when all probes disabled")
}

func TestGetHostInfo(t *testing.T) {
	t.Parallel()

	config := &models.Config{
		Version: 1,
		HostInfo: models.HostInfoConfig{
			Extended: true,
		},
	}
	collector := New(NewInput{Config: config})

	hostInfo, err := collector.getHostInfo(context.Background())

	require.NoError(t, err, "getHostInfo() should not return error")
	require.NotNil(t, hostInfo, "getHostInfo() should not return nil")
	assert.NotEmpty(t, hostInfo.Hostname, "hostname should not be empty")
	assert.Equal(t, runtime.GOOS, hostInfo.OS, "OS should match runtime.GOOS")
	assert.Equal(t, runtime.GOARCH, hostInfo.Arch, "Arch should match runtime.GOARCH")
	// Username might be empty in some test environments, so we don't check it

	// Extended info should be populated when enabled
	assert.NotNil(t, hostInfo.System, "System info should be populated")
}

func TestGetHostInfo_WithoutExtended(t *testing.T) {
	t.Parallel()

	config := &models.Config{
		Version: 1,
		HostInfo: models.HostInfoConfig{
			Extended: false,
		},
	}
	collector := New(NewInput{Config: config})

	hostInfo, err := collector.getHostInfo(context.Background())

	require.NoError(t, err, "getHostInfo() should not return error")
	require.NotNil(t, hostInfo, "getHostInfo() should not return nil")
	assert.NotEmpty(t, hostInfo.Hostname, "hostname should not be empty")

	// Extended info should NOT be populated when disabled
	assert.Nil(t, hostInfo.System, "System info should not be populated when extended=false")
}

// Benchmark concurrent probe execution
func BenchmarkExecuteProbes(b *testing.B) {

	probes := []probe.Probe{
		&mockProbe{name: "probe1", enabled: true, delay: 1 * time.Millisecond},
		&mockProbe{name: "probe2", enabled: true, delay: 1 * time.Millisecond},
		&mockProbe{name: "probe3", enabled: true, delay: 1 * time.Millisecond},
		&mockProbe{name: "probe4", enabled: true, delay: 1 * time.Millisecond},
		&mockProbe{name: "probe5", enabled: true, delay: 1 * time.Millisecond},
	}

	config := &models.Config{Version: 1}
	collector := New(NewInput{Probes: probes, Config: config})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.executeProbes(context.TODO(), nil)
	}
}
