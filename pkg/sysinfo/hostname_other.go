// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !darwin

package sysinfo

import "fmt"

func getStableHostname() (string, error) {
	hostname, err := osHostname()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}

	return hostname, nil
}
