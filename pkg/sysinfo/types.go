// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import "time"

// SystemInfo contains detailed system information
type SystemInfo struct {
	OSVersion     string    `json:"os_version,omitempty"`
	KernelVersion string    `json:"kernel_version,omitempty"`
	CPUModel      string    `json:"cpu_model,omitempty"`
	CPUCores      int       `json:"cpu_cores,omitempty"`
	RAMTotalGB    float64   `json:"ram_total_gb,omitempty"`
	BootTime      time.Time `json:"boot_time,omitempty"`
	Timezone      string    `json:"timezone,omitempty"`
}

// ExtendedInfo holds all extended host information
type ExtendedInfo struct {
	System *SystemInfo `json:"system,omitempty"`
}
