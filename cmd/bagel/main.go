// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"github.com/rs/zerolog/log"
)

func main() {
	if err := Execute(); err != nil {
		log.Fatal().Err(err).Msg("Command execution failed")
	}
}
