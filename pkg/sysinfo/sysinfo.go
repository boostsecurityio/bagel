// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

// Package sysinfo collects detailed system information
// to demonstrate what data info stealers can access on developer machines.
package sysinfo

import (
	"context"
	"time"

	"github.com/rs/zerolog"
)

const defaultTimeout = 5 * time.Second

// Collect gathers extended system information.
// It uses graceful degradation - if collection fails, it is logged
// and the function returns partial information.
func Collect(ctx context.Context) (*ExtendedInfo, error) {
	logger := zerolog.Ctx(ctx)
	info := &ExtendedInfo{}

	// Collect system info with timeout
	systemCtx, systemCancel := context.WithTimeout(ctx, defaultTimeout)
	defer systemCancel()

	systemInfo, err := collectSystemInfo(systemCtx)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to collect system info")
	} else {
		info.System = systemInfo
	}

	return info, nil
}
