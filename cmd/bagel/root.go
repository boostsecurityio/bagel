// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/logger"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "bagel",
	Short: "A Developer Endpoint Posture Scanner",
	Long: `Bagel is a cross-platform CLI that inspects developer workstations
and produces a structured report of installed dev tools, secret locations
(metadata only), and system/shell posture.

The report can feed into SIEMs, policy engines, or MDM/EPP platforms.`,
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
	},
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

	// Bind flags to viper
	if err := viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose")); err != nil {
		log := zerolog.New(os.Stderr).With().Timestamp().Logger()
		log.Fatal().Err(err).Msg("Error binding verbose flag")
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

	// Config file reading will be logged in PersistentPreRun after logger is setup
}
