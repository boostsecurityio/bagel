// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/logger"
	"github.com/boostsecurityio/bagel/pkg/versioncheck"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile             string
	verbose             bool
	disableVersionCheck bool
)
var (
	Version string
	Commit  string
	Date    string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "bagel",
	Short: "Scan developer workstations for security misconfigurations and exposed secrets",
	Long: `Bagel scans your development environment for security risks:

  - Exposed secrets in git config, shell history, env vars, and dotfiles
  - Insecure settings in SSH, git, npm, cloud CLIs, and IDE configs
  - Credential files for AWS, GCP, Azure, GitHub, and AI services

Bagel never reads secret values — it only reports metadata and locations.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Setup logger and attach to context
		log := logger.Setup(verbose)
		ctx := log.WithContext(cmd.Context())
		cmd.SetContext(ctx)

		// Log config file usage if available
		if cfgUsed := viper.ConfigFileUsed(); cfgUsed != "" {
			log.Debug().Str("config_file", cfgUsed).Msg("Using config file")
		}

		runVersionCheck(cmd)
	},
}

// versionCheckSkipCommands lists subcommands that must not trigger the
// version check: "completion" is invoked by shells for tab-completion
// lookups. Other subcommands (including "version" and "help") still pay the
// once-per-day check, since the 24h cache means at most one network call.
var versionCheckSkipCommands = map[string]struct{}{
	"completion": {},
}

// runVersionCheck performs the once-per-day update check unless disabled by
// flag, env var, or config. Commands listed in versionCheckSkipCommands and
// any subcommand under them are excluded so users can run shell completion
// without triggering a network call.
func runVersionCheck(cmd *cobra.Command) {
	for c := cmd; c != nil; c = c.Parent() {
		if _, skip := versionCheckSkipCommands[c.Name()]; skip {
			return
		}
	}
	disabled := disableVersionCheck || viper.GetBool("disable_version_check")
	ctx := cmd.Context()
	result := versioncheck.Run(ctx, Version, disabled)
	if result == nil || !result.UpdateAvailable {
		return
	}
	target := result.LatestURL
	if target == "" {
		target = "https://github.com/boostsecurityio/bagel/releases"
	}
	zerolog.Ctx(ctx).Warn().
		Str("current_version", Version).
		Str("latest_version", result.LatestVersion).
		Msgf("A new version of bagel is available: %s — %s", result.LatestVersion, target)
}

// Execute runs the root command
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("failed to execute command: %w", err)
	}
	return nil
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is "+config.GetConfigHelpPath()+")")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&disableVersionCheck, "disable-version-check", false, "Disable the once-per-day check for newer bagel releases")

	// Bind flags to viper
	if err := viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")); err != nil {
		log := zerolog.New(os.Stderr).With().Timestamp().Logger()
		log.Fatal().Err(err).Msg("Error binding verbose flag")
	}
	if err := viper.BindPFlag("disable_version_check", rootCmd.PersistentFlags().Lookup("disable-version-check")); err != nil {
		log := zerolog.New(os.Stderr).With().Timestamp().Logger()
		log.Fatal().Err(err).Msg("Error binding disable-version-check flag")
	}
}

// initConfig reads in config file and ENV variables
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(config.GetConfigDir())
		viper.AddConfigPath(".")
		viper.SetConfigName("bagel")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("BAGEL")
	viper.AutomaticEnv()

	// Read config so disable_version_check is available in PersistentPreRun.
	// Errors here are non-fatal; scan command performs its own validated load.
	_ = viper.ReadInConfig()
}
