// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Setup initializes and returns a configured zerolog logger
func Setup(verbose bool) zerolog.Logger {
	// Configure console output with human-friendly formatting
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}

	// Set log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// Create logger
	return zerolog.New(output).With().Timestamp().Logger()
}

// SetupWithOutput initializes a logger with a custom output writer
func SetupWithOutput(verbose bool, output io.Writer) zerolog.Logger {
	// Set log level
	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}

	// Create logger with custom output
	return zerolog.New(output).Level(level).With().Timestamp().Logger()
}
