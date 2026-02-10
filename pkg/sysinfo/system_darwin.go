//go:build darwin

// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// collectSystemInfo gathers macOS-specific system information
func collectSystemInfo(ctx context.Context) (*SystemInfo, error) {
	logger := zerolog.Ctx(ctx)
	info := &SystemInfo{}

	// Collect OS version using sw_vers
	if osVersion, err := getOSVersion(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get OS version")
	} else {
		info.OSVersion = osVersion
	}

	// Collect kernel version using uname
	if kernelVersion, err := getKernelVersion(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get kernel version")
	} else {
		info.KernelVersion = kernelVersion
	}

	// Collect CPU info using sysctl
	if cpuModel, err := getCPUModel(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get CPU model")
	} else {
		info.CPUModel = cpuModel
	}

	if cpuCores, err := getCPUCores(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get CPU cores")
	} else {
		info.CPUCores = cpuCores
	}

	// Collect RAM info using sysctl
	if ramGB, err := getRAMTotalGB(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get RAM total")
	} else {
		info.RAMTotalGB = ramGB
	}

	// Collect boot time using sysctl
	if bootTime, err := getBootTime(ctx); err != nil {
		logger.Debug().Err(err).Msg("Failed to get boot time")
	} else {
		info.BootTime = bootTime
	}

	// Collect timezone
	if tz, err := getTimezone(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get timezone")
	} else {
		info.Timezone = tz
	}

	return info, nil
}

// getOSVersion retrieves macOS version using sw_vers
func getOSVersion(ctx context.Context) (string, error) {
	productName, err := runCommand(ctx, "sw_vers", "-productName")
	if err != nil {
		return "", fmt.Errorf("get product name: %w", err)
	}

	productVersion, err := runCommand(ctx, "sw_vers", "-productVersion")
	if err != nil {
		return "", fmt.Errorf("get product version: %w", err)
	}

	// Try to get the friendly name (e.g., "Sonoma")
	buildVersion, _ := runCommand(ctx, "sw_vers", "-buildVersion")

	result := fmt.Sprintf("%s %s", strings.TrimSpace(productName), strings.TrimSpace(productVersion))
	if buildVersion != "" {
		result += fmt.Sprintf(" (%s)", strings.TrimSpace(buildVersion))
	}

	return result, nil
}

// getKernelVersion retrieves Darwin kernel version
func getKernelVersion(ctx context.Context) (string, error) {
	output, err := runCommand(ctx, "uname", "-r")
	if err != nil {
		return "", fmt.Errorf("run uname: %w", err)
	}
	return strings.TrimSpace(output), nil
}

// getCPUModel retrieves CPU brand string
func getCPUModel(ctx context.Context) (string, error) {
	output, err := runCommand(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
	if err != nil {
		// Fallback for Apple Silicon which may not have brand_string
		output, err = runCommand(ctx, "sysctl", "-n", "hw.model")
		if err != nil {
			return "", fmt.Errorf("get CPU model: %w", err)
		}
	}
	return strings.TrimSpace(output), nil
}

// getCPUCores retrieves the number of logical CPU cores
func getCPUCores(ctx context.Context) (int, error) {
	output, err := runCommand(ctx, "sysctl", "-n", "hw.logicalcpu")
	if err != nil {
		return 0, fmt.Errorf("get logical CPU count: %w", err)
	}

	cores, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return 0, fmt.Errorf("parse CPU cores: %w", err)
	}

	return cores, nil
}

// getRAMTotalGB retrieves total RAM in gigabytes
func getRAMTotalGB(ctx context.Context) (float64, error) {
	output, err := runCommand(ctx, "sysctl", "-n", "hw.memsize")
	if err != nil {
		return 0, fmt.Errorf("get memory size: %w", err)
	}

	memBytes, err := strconv.ParseInt(strings.TrimSpace(output), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse memory size: %w", err)
	}

	// Convert bytes to GB with 1 decimal place precision
	memGB := float64(memBytes) / (1024 * 1024 * 1024)
	return float64(int(memGB*10)) / 10, nil
}

// getBootTime retrieves system boot time
func getBootTime(ctx context.Context) (time.Time, error) {
	output, err := runCommand(ctx, "sysctl", "-n", "kern.boottime")
	if err != nil {
		return time.Time{}, fmt.Errorf("get boot time: %w", err)
	}

	// Output format: { sec = 1706789012, usec = 123456 } Mon Feb  1 08:30:12 2024
	// Extract the sec value
	trimmed := strings.TrimSpace(output)
	secIdx := strings.Index(trimmed, "sec = ")
	if secIdx == -1 {
		return time.Time{}, errors.New("parse boot time: unexpected format")
	}

	secStr := trimmed[secIdx+6:]
	commaIdx := strings.Index(secStr, ",")
	if commaIdx == -1 {
		return time.Time{}, errors.New("parse boot time: missing comma")
	}

	secValue, err := strconv.ParseInt(secStr[:commaIdx], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse boot time seconds: %w", err)
	}

	return time.Unix(secValue, 0), nil
}

// getTimezone retrieves the current timezone
func getTimezone() (string, error) {
	tz, err := time.LoadLocation("Local")
	if err != nil {
		return "", fmt.Errorf("load local timezone: %w", err)
	}
	return tz.String(), nil
}

// runCommand executes a command and returns its output
func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("run %s: %w (stderr: %s)", name, err, stderr.String())
	}

	return stdout.String(), nil
}
