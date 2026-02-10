// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollect(t *testing.T) {
	t.Parallel()

	ctx := zerolog.New(zerolog.NewTestWriter(t)).WithContext(context.Background())

	info, err := Collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)

	// System info should be collected (may have partial data)
	assert.NotNil(t, info.System)
}

func TestCollect_SystemInfo(t *testing.T) {
	t.Parallel()

	ctx := zerolog.New(zerolog.NewTestWriter(t)).WithContext(context.Background())

	info, err := Collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, info.System)

	// These fields should be populated on any platform
	assert.NotEmpty(t, info.System.OSVersion, "OS version should be populated")
	assert.NotEmpty(t, info.System.KernelVersion, "Kernel version should be populated")
	assert.Positive(t, info.System.CPUCores, "CPU cores should be > 0")
	assert.Positive(t, info.System.RAMTotalGB, "RAM should be > 0")
	assert.NotEmpty(t, info.System.Timezone, "Timezone should be populated")

	// Boot time should be in the past
	if !info.System.BootTime.IsZero() {
		assert.True(t, info.System.BootTime.Before(time.Now()), "Boot time should be in the past")
	}
}

func TestCollect_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Should still return partial results even with cancelled context
	info, err := Collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)
}

func TestCollect_Timeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Should complete within timeout
	info, err := Collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, info)
}

func TestSystemInfo_Fields(t *testing.T) {
	t.Parallel()

	bootTime := time.Date(2024, 2, 1, 8, 30, 0, 0, time.UTC)
	sys := SystemInfo{
		OSVersion:     "macOS 14.2",
		KernelVersion: "23.2.0",
		CPUModel:      "Apple M2 Pro",
		CPUCores:      12,
		RAMTotalGB:    32.0,
		BootTime:      bootTime,
		Timezone:      "America/New_York",
	}

	assert.Equal(t, "macOS 14.2", sys.OSVersion)
	assert.Equal(t, "23.2.0", sys.KernelVersion)
	assert.Equal(t, "Apple M2 Pro", sys.CPUModel)
	assert.Equal(t, 12, sys.CPUCores)
	assert.InDelta(t, 32.0, sys.RAMTotalGB, 0.001)
	assert.Equal(t, bootTime, sys.BootTime)
	assert.Equal(t, "America/New_York", sys.Timezone)
}

func TestExtendedInfo_Empty(t *testing.T) {
	t.Parallel()

	info := &ExtendedInfo{}
	assert.Nil(t, info.System)
}
