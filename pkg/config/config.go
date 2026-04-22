// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/spf13/viper"
)

// Load reads configuration from file and environment variables
func Load(configPath string) (*models.Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Set config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in standard locations
		v.SetConfigName("bagel")
		v.SetConfigType("yaml")
		v.AddConfigPath(GetConfigDir())
		v.AddConfigPath(".")
	}

	// Read environment variables
	v.SetEnvPrefix("BAGEL")
	v.AutomaticEnv()

	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults
	}

	// Unmarshal config
	var cfg models.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	v.SetDefault("version", 1)
	v.SetDefault("probes.git.enabled", true)
	v.SetDefault("probes.env.enabled", true)
	v.SetDefault("probes.ssh.enabled", true)
	v.SetDefault("probes.npm.enabled", true)
	v.SetDefault("probes.shell_history.enabled", true)
	v.SetDefault("probes.cloud.enabled", true)
	v.SetDefault("probes.jetbrains.enabled", true)
	v.SetDefault("probes.gh.enabled", true)
	v.SetDefault("probes.ai_cli.enabled", true)
	v.SetDefault("probes.wireguard.enabled", true)
	v.SetDefault("probes.pypi.enabled", true)
	v.SetDefault("output.include_file_hashes", false)
	v.SetDefault("output.include_file_content", false)

	// Host info defaults
	v.SetDefault("hostinfo.extended", true)

	// File index defaults
	v.SetDefault("file_index.max_depth", 0) // 0 = unlimited
	v.SetDefault("file_index.follow_symlinks", false)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "." // Fallback to current directory
	}
	v.SetDefault("file_index.base_dirs", []string{homeDir})

	// Default exclude paths — directories we don't expect to find user config
	// or secrets in but that typically contain millions of files. Entries with
	// no path separator are treated as basenames and pruned at any depth (so
	// "node_modules" skips every nested node_modules); absolute / ~-prefixed
	// entries prune that specific directory tree. Entries for platforms other
	// than the current OS are harmless no-ops.
	v.SetDefault("file_index.exclude_paths", []string{
		// Basename prunes (match at any depth)
		"node_modules",
		"__pycache__",
		".tox",
		// macOS system caches / build output
		"~/Library/Caches",
		"~/Library/Logs",
		"~/Library/Developer/Xcode/DerivedData",
		"~/.Trash",
		// XDG cache (Linux, also used by some cross-platform tools on macOS)
		"~/.cache",
		// Language / package-manager caches
		"~/go/pkg/mod",
		"~/.gradle/caches",
		"~/.m2/repository",
		"~/.npm/_cacache",
	})

	// Cache staleness detection defaults
	v.SetDefault("file_index.cache.ttl", "30m")
	v.SetDefault("file_index.cache.sample_size", 50)
	v.SetDefault("file_index.cache.validate_on_load", true)

	// Common dotfiles and config files
	v.SetDefault("file_index.patterns", []map[string]interface{}{
		// SSH
		{"name": "ssh_config", "patterns": []string{".ssh/config"}, "type": "glob"},
		{"name": "ssh_known_hosts", "patterns": []string{".ssh/known_hosts"}, "type": "glob"},
		{"name": "ssh_keys", "patterns": []string{".ssh/id_*", ".ssh/*.pem"}, "type": "glob"},
		{"name": "ssh_authorized_keys", "patterns": []string{".ssh/authorized_keys"}, "type": "glob"},

		// Git
		{"name": "gitconfig", "patterns": []string{".gitconfig", ".config/git/config", ".git/config"}, "type": "glob"},
		{"name": "gitignore_global", "patterns": []string{".gitignore_global", ".config/git/ignore"}, "type": "glob"},
		{"name": "git_credentials", "patterns": []string{".git-credentials", ".config/git/credentials"}, "type": "glob"},

		// NPM
		{"name": "npmrc", "patterns": []string{".npmrc", ".config/npm/npmrc"}, "type": "glob"},

		// Yarn
		{"name": "yarnrc", "patterns": []string{".yarnrc", ".yarnrc.yml"}, "type": "glob"},

		// AWS
		{"name": "aws_config", "patterns": []string{".aws/config"}, "type": "glob"},
		{"name": "aws_credentials", "patterns": []string{".aws/credentials"}, "type": "glob"},

		// Google Cloud (GCP) - Unix: ~/.config/gcloud, Windows: %APPDATA%\gcloud
		{"name": "gcp_config", "patterns": []string{
			".config/gcloud/configurations/config_*",
			".config/gcloud/properties",
			// Windows: %APPDATA%\gcloud
			"AppData/Roaming/gcloud/configurations/config_*",
			"AppData/Roaming/gcloud/properties",
		}, "type": "glob"},
		{"name": "gcp_credentials", "patterns": []string{
			".config/gcloud/credentials.db",
			".config/gcloud/legacy_credentials/*",
			".config/gcloud/application_default_credentials.json",
			".config/gcloud/adc.json",
			".config/gcloud/access_tokens.db",
			// Windows paths
			"AppData/Roaming/gcloud/credentials.db",
			"AppData/Roaming/gcloud/legacy_credentials/*",
			"AppData/Roaming/gcloud/application_default_credentials.json",
			"AppData/Roaming/gcloud/adc.json",
			"AppData/Roaming/gcloud/access_tokens.db",
		}, "type": "glob"},

		// Azure - Unix: ~/.azure, Windows: %USERPROFILE%\.azure or %APPDATA%\.azure
		{"name": "azure_config", "patterns": []string{
			".azure/config",
			".azure/clouds.config",
			".azure/azureProfile.json",
			// Windows paths
			"AppData/Roaming/.azure/config",
			"AppData/Roaming/.azure/clouds.config",
			"AppData/Roaming/.azure/azureProfile.json",
		}, "type": "glob"},

		// Docker
		{"name": "docker_config", "patterns": []string{".docker/config.json"}, "type": "glob"},

		// Kubernetes
		{"name": "kubeconfig", "patterns": []string{".kube/config"}, "type": "glob"},

		// Shell configs
		{"name": "bashrc", "patterns": []string{".bashrc", ".bash_profile", ".profile"}, "type": "glob"},
		{"name": "zshrc", "patterns": []string{".zshrc", ".zprofile"}, "type": "glob"},

		// Shell history files - Unix shells and PowerShell (Windows)
		{"name": "shell_history", "patterns": []string{
			".bash_history",
			".zsh_history",
			".sh_history",
			".history",
			".local/share/fish/fish_history",
			// PowerShell history (Windows)
			"AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
		}, "type": "glob"},

		// Environment files
		{"name": "env_files", "patterns": []string{".env", ".env.*"}, "type": "glob"},

		// JetBrains
		{"name": "jetbrains", "patterns": []string{".idea/workspace.xml"}, "type": "glob"},

		// AI tools
		{"name": "gemini_credentials", "patterns": []string{".gemini/oauth_creds.json"}, "type": "glob"},
		{"name": "codex_credentials", "patterns": []string{".codex/auth.json"}, "type": "glob"},
		{"name": "opencode_credentials", "patterns": []string{".local/share/opencode/auth.json"}, "type": "glob"},

		{"name": "gemini_chats", "patterns": []string{".gemini/tmp/*/chats/*.json"}, "type": "glob"},
		{"name": "codex_chats", "patterns": []string{".codex/sessions/*/*/*/rollout-*.jsonl"}, "type": "glob"},
		{"name": "claude_chats", "patterns": []string{".claude/projects/*/*.jsonl"}, "type": "glob"},
		{"name": "opencode_chats", "patterns": []string{".local/share/opencode/storage/part/msg_*/prt_*.json"}, "type": "glob"},

		// WireGuard (user-level configs; system paths are checked directly by the probe)
		{"name": "wireguard_config", "patterns": []string{".config/wireguard/*.conf"}, "type": "glob"},

		// HashiCorp Vault
		{"name": "vault_token", "patterns": []string{".vault-token"}, "type": "glob"},

		// PyPI
		{"name": "pypirc", "patterns": []string{".pypirc"}, "type": "glob"},
		{"name": "pip_config", "patterns": []string{
			".pip/pip.conf",
			".config/pip/pip.conf",
			// macOS
			"Library/Application Support/pip/pip.conf",
			// Windows
			"AppData/Roaming/pip/pip.ini",
		}, "type": "glob"},
	})
}

// GetConfigDir returns the platform-appropriate configuration directory for bagel.
// On Windows: %APPDATA%\bagel
// On Unix: ~/.config/bagel
func GetConfigDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "bagel")
		}
	}

	// Unix: ~/.config/bagel
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".config", "bagel")
	}
	return filepath.Join(home, ".config", "bagel")
}

// GetConfigHelpPath returns a user-friendly representation of the config path for help text.
func GetConfigHelpPath() string {
	if runtime.GOOS == "windows" {
		return "%APPDATA%\\bagel\\bagel.yaml"
	}
	return "$HOME/.config/bagel/bagel.yaml"
}
