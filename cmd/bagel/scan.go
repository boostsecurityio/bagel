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

// initializeProbes creates and configures all probes
func initializeProbes(cfg *models.Config) []probe.Probe {
	var probes []probe.Probe

	// Create detector registry and register all secret detectors
	registry := detector.NewRegistry()
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())
	registry.Register(detector.NewSSHPrivateKeyDetector())
	registry.Register(detector.NewAIServiceDetector())
	registry.Register(detector.NewHTTPAuthDetector())
	registry.Register(detector.NewCloudCredentialsDetector())
	registry.Register(detector.NewVaultTokenDetector())
	registry.Register(detector.NewPyPITokenDetector())
	registry.Register(detector.NewWireGuardKeyDetector())
	registry.Register(detector.NewGenericAPIKeyDetector())
	registry.Register(detector.NewJWTDetector())
	// Add more detectors here as they are implemented:
	// registry.Register(detector.NewSlackTokenDetector())
	// etc.

	// Git probe
	if cfg.Probes.Git.Enabled {
		probes = append(probes, probe.NewGitProbe(cfg.Probes.Git, registry))
	}

	// Environment variable probe
	if cfg.Probes.Env.Enabled {
		probes = append(probes, probe.NewEnvProbe(cfg.Probes.Env, registry))
	}

	// NPM probe
	if cfg.Probes.NPM.Enabled {
		probes = append(probes, probe.NewNPMProbe(cfg.Probes.NPM, registry))
	}

	// SSH probe
	if cfg.Probes.SSH.Enabled {
		probes = append(probes, probe.NewSSHProbe(cfg.Probes.SSH, registry))
	}

	// Shell history probe
	if cfg.Probes.ShellHistory.Enabled {
		probes = append(probes, probe.NewShellHistoryProbe(cfg.Probes.ShellHistory, registry))
	}

	// Cloud credentials probe
	if cfg.Probes.Cloud.Enabled {
		probes = append(probes, probe.NewCloudProbe(cfg.Probes.Cloud, registry))
	}

	// JetBrains probe
	if cfg.Probes.JetBrains.Enabled {
		probes = append(probes, probe.NewJetBrainsProbe(cfg.Probes.JetBrains, registry))
	}

	// GitHub CLI probe
	if cfg.Probes.GH.Enabled {
		probes = append(probes, probe.NewGHProbe(cfg.Probes.GH, registry))
	}

	// AI CLI probe
	if cfg.Probes.AICli.Enabled {
		probes = append(probes, probe.NewAICliProbe(cfg.Probes.AICli, registry))
	}

	// WireGuard probe
	if cfg.Probes.WireGuard.Enabled {
		probes = append(probes, probe.NewWireGuardProbe(cfg.Probes.WireGuard, registry))
	}

	// PyPI probe
	if cfg.Probes.PyPI.Enabled {
		probes = append(probes, probe.NewPyPIProbe(cfg.Probes.PyPI, registry))
	}

	return probes
}
