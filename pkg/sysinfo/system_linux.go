//go:build linux

// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// collectSystemInfo gathers Linux-specific system information
func collectSystemInfo(ctx context.Context) (*SystemInfo, error) {
	logger := zerolog.Ctx(ctx)
	info := &SystemInfo{}

	// Collect OS version from /etc/os-release
	if osVersion, err := getOSVersion(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get OS version")
	} else {
		info.OSVersion = osVersion
	}

	// Collect kernel version from /proc/version
	if kernelVersion, err := getKernelVersion(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get kernel version")
	} else {
		info.KernelVersion = kernelVersion
	}

	// Collect CPU info from /proc/cpuinfo
	if cpuModel, err := getCPUModel(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get CPU model")
	} else {
		info.CPUModel = cpuModel
	}

	if cpuCores, err := getCPUCores(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get CPU cores")
	} else {
		info.CPUCores = cpuCores
	}

	// Collect RAM info from /proc/meminfo
	if ramGB, err := getRAMTotalGB(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get RAM total")
	} else {
		info.RAMTotalGB = ramGB
	}

	// Collect boot time from /proc/uptime
	if bootTime, err := getBootTime(); err != nil {
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

// getOSVersion retrieves OS version from /etc/os-release
func getOSVersion() (string, error) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("open os-release: %w", err)
	}
	defer file.Close()

	var prettyName string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			prettyName = strings.Trim(line[12:], "\"")
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan os-release: %w", err)
	}

	if prettyName == "" {
		return "", errors.New("PRETTY_NAME not found in os-release")
	}

	return prettyName, nil
}

// getKernelVersion retrieves kernel version from uname -r
func getKernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("read /proc/version: %w", err)
	}

	// Format: Linux version 5.15.0-generic ...
	parts := strings.Fields(string(data))
	if len(parts) >= 3 {
		return parts[2], nil
	}

	return "", errors.New("parse kernel version: unexpected format")
}

// getCPUModel retrieves CPU model from /proc/cpuinfo
func getCPUModel() (string, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "", fmt.Errorf("open cpuinfo: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan cpuinfo: %w", err)
	}

	return "", errors.New("model name not found in cpuinfo")
}

// getCPUCores retrieves the number of logical CPU cores
func getCPUCores() (int, error) {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return 0, fmt.Errorf("open cpuinfo: %w", err)
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan cpuinfo: %w", err)
	}

	if count == 0 {
		return 0, errors.New("no processors found in cpuinfo")
	}

	return count, nil
}

// getRAMTotalGB retrieves total RAM in gigabytes from /proc/meminfo
func getRAMTotalGB() (float64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("open meminfo: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			// Format: MemTotal:       16384000 kB
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memKB, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return 0, fmt.Errorf("parse MemTotal: %w", err)
				}
				// Convert KB to GB with 1 decimal place precision
				memGB := float64(memKB) / (1024 * 1024)
				return float64(int(memGB*10)) / 10, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan meminfo: %w", err)
	}

	return 0, errors.New("MemTotal not found in meminfo")
}

// getBootTime calculates boot time from /proc/uptime
func getBootTime() (time.Time, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, fmt.Errorf("read uptime: %w", err)
	}

	// Format: 12345.67 98765.43 (uptime in seconds, idle time)
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return time.Time{}, errors.New("parse uptime: unexpected format")
	}

	uptimeSeconds, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse uptime seconds: %w", err)
	}

	bootTime := time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second)))
	return bootTime, nil
}

// getTimezone retrieves the current timezone
func getTimezone() (string, error) {
	tz, err := time.LoadLocation("Local")
	if err != nil {
		return "", fmt.Errorf("load local timezone: %w", err)
	}
	return tz.String(), nil
}
