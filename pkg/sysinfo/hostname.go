// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package sysinfo

import "os"

// GetStableHostname returns a hostname that is stable across network changes.
// On macOS, it uses scutil --get LocalHostName which returns the user-set
// ComputerName rather than the DHCP-assigned name. Falls back to os.Hostname().
func GetStableHostname() (string, error) {
	return getStableHostname()
}

// osHostname is a package-level variable to allow testing without overriding os.Hostname.
var osHostname = os.Hostname
