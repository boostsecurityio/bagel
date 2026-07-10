// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/boostsecurityio/bagel/pkg/collector"
	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/boostsecurityio/bagel/pkg/probe"
	"github.com/boostsecurityio/bagel/pkg/reporter"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	outputFormat string
	outputFile   string
	strict       bool
	noCache      bool
	noProgress   bool
	baseDirs     []string
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan the local system for security posture",
	Long: `Scan inspects the developer workstation and produces a structured report
of installed dev tools, secret locations (metadata only), and system/shell posture.`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "output format (json, table)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default is stdout)")
	scanCmd.Flags().BoolVar(&strict, "strict", false, "exit with code 2 if any findings are detected")
	scanCmd.Flags().BoolVar(&noCache, "no-cache", false, "bypass file index cache and force rebuild")
	scanCmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable progress bars")
	scanCmd.Flags().StringSliceVar(&baseDirs, "base-dirs", nil,
		"comma-separated directories to scan; overrides file_index.base_dirs. "+
			"e.g. --base-dirs /home,/Users,/root")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Get context with logger from root command
	ctx := cmd.Context()
	log := zerolog.Ctx(ctx)

	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// --base-dir takes precedence over config/defaults
	if len(baseDirs) > 0 {
		cfg.FileIndex.BaseDirs = baseDirs
		log.Debug().Strs("base_dirs", baseDirs).Msg("Overriding base dirs from --base-dirs")
	}

	log.Debug().Msg("Starting scan")

	// Initialize probes
	probes := initializeProbes(cfg)

	log.Debug().Int("probe_count", len(probes)).Msg("Initialized probes")

	// Create collector
	col := collector.New(collector.NewInput{
		Probes:     probes,
		Config:     cfg,
		NoCache:    noCache,
		NoProgress: noProgress,
	})

	// Execute scan
	result, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	log.Info().Int("finding_count", len(result.Findings)).Msg("Scan complete")

	// Determine output destination
	output := os.Stdout
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		output = f
	}

	// Create reporter and output results
	format := reporter.Format(outputFormat)
	rep := reporter.New(format, output)

	if err := rep.Report(result); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Handle exit codes
	if strict && len(result.Findings) > 0 {
		os.Exit(2)
	}

	return nil
}

// initializeProbes builds the default probe set and keeps only the enabled ones.
// The collector also filters on IsEnabled at execution time, but filtering here
// preserves the historical probe slice (and probe_count log) exactly.
func initializeProbes(cfg *models.Config) []probe.Probe {
	registry := detector.NewDefaultRegistry()

	var probes []probe.Probe
	for _, p := range probe.DefaultProbes(cfg, registry) {
		if p.IsEnabled() {
			probes = append(probes, p)
		}
	}
	return probes
}
