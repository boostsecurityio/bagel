//go:build windows

// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"context"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// memoryStatusEx corresponds to the Windows MEMORYSTATUSEX structure
type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// collectSystemInfo gathers Windows-specific system information
func collectSystemInfo(ctx context.Context) (*SystemInfo, error) {
	logger := zerolog.Ctx(ctx)
	info := &SystemInfo{}

	// Collect OS version using Windows API
	if osVersion, err := getOSVersion(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get OS version")
	} else {
		info.OSVersion = osVersion
	}

	// Collect kernel/build version
	if kernelVersion, err := getKernelVersion(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get kernel version")
	} else {
		info.KernelVersion = kernelVersion
	}

	// Collect CPU info
	if cpuModel, err := getCPUModel(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get CPU model")
	} else {
		info.CPUModel = cpuModel
	}

	info.CPUCores = getCPUCores()

	// Collect RAM info using Windows API
	if ramGB, err := getRAMTotalGB(); err != nil {
		logger.Debug().Err(err).Msg("Failed to get RAM total")
	} else {
		info.RAMTotalGB = ramGB
	}

	// Collect boot time using Windows API
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

// getOSVersion retrieves Windows version using RtlGetVersion API
func getOSVersion() (string, error) {
	vi := windows.RtlGetVersion()
	if vi == nil {
		return "", fmt.Errorf("get OS version: RtlGetVersion returned nil")
	}

	// Map version numbers to Windows edition names
	osName := mapWindowsVersion(vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)

	return fmt.Sprintf("%s (%d.%d.%d)", osName, vi.MajorVersion, vi.MinorVersion, vi.BuildNumber), nil
}

// mapWindowsVersion maps Windows version numbers to edition names
func mapWindowsVersion(major, minor, build uint32) string {
	switch {
	case major == 10 && minor == 0 && build >= 22000:
		return "Windows 11"
	case major == 10 && minor == 0:
		return "Windows 10"
	case major == 6 && minor == 3:
		return "Windows 8.1"
	case major == 6 && minor == 2:
		return "Windows 8"
	case major == 6 && minor == 1:
		return "Windows 7"
	default:
		return fmt.Sprintf("Windows %d.%d", major, minor)
	}
}

// getKernelVersion retrieves Windows build number
func getKernelVersion() (string, error) {
	vi := windows.RtlGetVersion()
	if vi == nil {
		return "", fmt.Errorf("get kernel version: RtlGetVersion returned nil")
	}

	return fmt.Sprintf("%d", vi.BuildNumber), nil
}

// getCPUModel retrieves CPU name from Windows Registry
func getCPUModel() (string, error) {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return "", fmt.Errorf("open registry key: %w", err)
	}
	defer key.Close()

	cpuName, _, err := key.GetStringValue("ProcessorNameString")
	if err != nil {
		return "", fmt.Errorf("read processor name: %w", err)
	}

	return cpuName, nil
}

// getCPUCores retrieves the number of logical processors using Go runtime
func getCPUCores() int {
	return runtime.NumCPU()
}

// getRAMTotalGB retrieves total RAM in gigabytes using GlobalMemoryStatusEx
func getRAMTotalGB() (float64, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	var memStatus memoryStatusEx
	memStatus.length = uint32(unsafe.Sizeof(memStatus))

	ret, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return 0, fmt.Errorf("get memory status: %w", err)
	}

	// Convert bytes to GB with 1 decimal place precision
	memGB := float64(memStatus.totalPhys) / (1024 * 1024 * 1024)
	return float64(int(memGB*10)) / 10, nil
}

// getBootTime calculates boot time using DurationSinceBoot
func getBootTime() (time.Time, error) {
	uptime := windows.DurationSinceBoot()
	bootTime := time.Now().Add(-uptime)
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
