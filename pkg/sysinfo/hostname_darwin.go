// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import (
	"fmt"
	"os/exec"
	"strings"
)

// execCommand is a package-level variable to allow testing.
var execCommand = exec.Command

func getStableHostname() (string, error) {
	cmd := execCommand("scutil", "--get", "LocalHostName")
	out, err := cmd.Output()
	if err == nil {
		hostname := strings.TrimSpace(string(out))
		if hostname != "" {
			return hostname, nil
		}
	}

	// Fallback to os.Hostname()
	hostname, err := osHostname()
	if err != nil {
		return "", fmt.Errorf("get hostname: %w", err)
	}

	return hostname, nil
}
