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
	"github.com/rs/zerolog/log"
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
		// Look for config in standard locations. We deliberately do NOT call
		// SetConfigType: with a type set, viper also matches an extensionless
		// file named "bagel" in the search path — so running `./bagel scan`
		// from the binary's own directory makes viper try to parse the bagel
		// binary as YAML ("control characters are not allowed"). Without a
		// type, viper only matches bagel.<ext>.
		v.SetConfigName("bagel")
		v.AddConfigPath(GetConfigDir())
		v.AddConfigPath(".")
	}

	// Read environment variables
	v.SetEnvPrefix("BAGEL")
	v.AutomaticEnv()

	// Read config file if it exists.
	// A missing or unreadable config must never block a scan
	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		switch {
		case errors.As(err, &configFileNotFoundError):
			log.Debug().Msg("config: no config file found; using built-in defaults")
		case configPath != "":
			return nil, fmt.Errorf("failed to read config file %q: %w", configPath, err)
		default:
			log.Warn().Err(err).Msg(
				"config: could not read a discovered config file; using built-in defaults")
		}
	}

	// Unmarshal config
	var cfg models.Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := applyLegacyAICliConfig(v, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// applyLegacyAICliConfig mirrors a deprecated probes.ai_cli block onto the
// new probes.ai_credentials and probes.ai_chats settings. The probe was
// split when scrub stopped touching credential files (issue #44); existing
// configs that disabled or tuned ai_cli should keep working without edits.
//
// We don't SetDefault ai_cli, so v.Get returns nil unless the user wrote it
// somewhere (config file, env, flag). When present, both new probes inherit
// the same enabled/flags — a user mixing legacy and new keys gets the
// legacy values, which the deprecation warning calls out.
func applyLegacyAICliConfig(v *viper.Viper, cfg *models.Config) error {
	if v.Get("probes.ai_cli") == nil {
		return nil
	}
	var legacy models.ProbeSettings
	if err := v.UnmarshalKey("probes.ai_cli", &legacy); err != nil {
		return fmt.Errorf("decode legacy probes.ai_cli: %w", err)
	}
	cfg.Probes.AICredentials = legacy
	cfg.Probes.AIChats = legacy
	log.Warn().Msg(
		"config: probes.ai_cli is deprecated; rename it to probes.ai_credentials " +
			"and probes.ai_chats (scrub no longer touches AI credential files).",
	)
	return nil
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
	v.SetDefault("probes.ai_credentials.enabled", true)
	v.SetDefault("probes.ai_chats.enabled", true)
	v.SetDefault("probes.wireguard.enabled", true)
	v.SetDefault("probes.pypi.enabled", true)
	v.SetDefault("probes.kube.enabled", true)
	v.SetDefault("probes.docker.enabled", true)
	v.SetDefault("probes.iac.enabled", true)
	v.SetDefault("probes.ai_mcp.enabled", true)
	v.SetDefault("probes.ai_context.enabled", true)
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
	// On Windows, also scan the home dirs of any installed WSL distro so Linux
	// secrets aren't a blindspot. No-op on other platforms.
	v.SetDefault("file_index.scan_wsl", true)

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

	// Resource caps. Zero / empty values preserve current unthrottled behavior;
	// daemon callers can tune these down.
	v.SetDefault("resources.file_index_workers", 0)
	v.SetDefault("resources.max_concurrent_probes", 0)
	v.SetDefault("resources.probe_timeout", "30s")

	// Common dotfiles and config files. Single source of truth is
	// DefaultPatterns; convert to viper's map shape here.
	defaults := DefaultPatterns()
	rawPatterns := make([]map[string]interface{}, len(defaults))
	for i, p := range defaults {
		rawPatterns[i] = map[string]interface{}{
			"name":     p.Name,
			"patterns": p.Patterns,
			"type":     p.Type,
		}
	}
	v.SetDefault("file_index.patterns", rawPatterns)
}

// DefaultPatterns returns the built-in file-index pattern groups bagel scans by
// default. Callers that want to extend (rather than replace) the defaults can
// append their own PatternConfig entries to the returned slice.
func DefaultPatterns() []models.PatternConfig {
	return []models.PatternConfig{
		// SSH
		{Name: "ssh_config", Patterns: []string{".ssh/config"}, Type: "glob"},
		{Name: "ssh_known_hosts", Patterns: []string{".ssh/known_hosts"}, Type: "glob"},
		{Name: "ssh_keys", Patterns: []string{".ssh/id_*", ".ssh/*.pem"}, Type: "glob"},
		{Name: "ssh_authorized_keys", Patterns: []string{".ssh/authorized_keys"}, Type: "glob"},

		// Git
		{Name: "gitconfig", Patterns: []string{".gitconfig", ".config/git/config", ".git/config"}, Type: "glob"},
		{Name: "gitignore_global", Patterns: []string{".gitignore_global", ".config/git/ignore"}, Type: "glob"},
		{Name: "git_credentials", Patterns: []string{".git-credentials", ".config/git/credentials"}, Type: "glob"},

		// NPM
		{Name: "npmrc", Patterns: []string{".npmrc", ".config/npm/npmrc"}, Type: "glob"},

		// Yarn
		{Name: "yarnrc", Patterns: []string{".yarnrc", ".yarnrc.yml"}, Type: "glob"},

		// AWS
		{Name: "aws_config", Patterns: []string{".aws/config"}, Type: "glob"},
		{Name: "aws_credentials", Patterns: []string{".aws/credentials"}, Type: "glob"},
		{Name: "aws_sso_cache", Patterns: []string{".aws/sso/cache/*.json"}, Type: "glob"},
		{Name: "aws_cli_cache", Patterns: []string{".aws/cli/cache/*.json"}, Type: "glob"},

		// Google Cloud (GCP) - Unix: ~/.config/gcloud, Windows: %APPDATA%\gcloud
		{Name: "gcp_config", Patterns: []string{
			".config/gcloud/configurations/config_*",
			".config/gcloud/properties",
			// Windows: %APPDATA%\gcloud
			"AppData/Roaming/gcloud/configurations/config_*",
			"AppData/Roaming/gcloud/properties",
		}, Type: "glob"},
		{Name: "gcp_credentials", Patterns: []string{
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
		}, Type: "glob"},

		// Azure - Unix: ~/.azure, Windows: %USERPROFILE%\.azure or %APPDATA%\.azure
		{Name: "azure_config", Patterns: []string{
			".azure/config",
			".azure/clouds.config",
			".azure/azureProfile.json",
			// Windows paths
			"AppData/Roaming/.azure/config",
			"AppData/Roaming/.azure/clouds.config",
			"AppData/Roaming/.azure/azureProfile.json",
		}, Type: "glob"},
		{Name: "azure_tokens", Patterns: []string{
			".azure/accessTokens.json",
			".azure/msal_token_cache.*",
			".azure/msazure.login/*",
			".azure/azd/*",
			"AppData/Roaming/.azure/accessTokens.json",
			"AppData/Roaming/.azure/msal_token_cache.*",
		}, Type: "glob"},
		{Name: "oci_config", Patterns: []string{
			".oci/config",
			".oci/sessions/*",
		}, Type: "glob"},
		{Name: "aliyun_config", Patterns: []string{".aliyun/config.json"}, Type: "glob"},
		{Name: "bluemix_config", Patterns: []string{".bluemix/config.json"}, Type: "glob"},
		{Name: "doctl_config", Patterns: []string{".config/doctl/config.yaml"}, Type: "glob"},
		{Name: "hcloud_config", Patterns: []string{".config/hcloud/cli.toml"}, Type: "glob"},
		{Name: "scw_config", Patterns: []string{".config/scw/config.yaml"}, Type: "glob"},
		{Name: "linode_config", Patterns: []string{".config/linode-cli/*"}, Type: "glob"},
		{Name: "fly_config", Patterns: []string{".fly/config.yml"}, Type: "glob"},
		{Name: "vercel_config", Patterns: []string{".vercel/auth.json"}, Type: "glob"},
		{Name: "railway_config", Patterns: []string{".railway/config.json"}, Type: "glob"},
		{Name: "snowflake_config", Patterns: []string{".snowflake/connections.toml"}, Type: "glob"},
		{Name: "doppler_config", Patterns: []string{".doppler.yaml"}, Type: "glob"},
		{Name: "gh_hosts", Patterns: []string{".config/gh/hosts.yml"}, Type: "glob"},
		{Name: "glab_config", Patterns: []string{".config/glab-cli/config.yml"}, Type: "glob"},
		{Name: "hub_config", Patterns: []string{".config/hub"}, Type: "glob"},
		{Name: "netrc_file", Patterns: []string{".netrc", "_netrc"}, Type: "glob"},

		// Kiro IDE MCP — same shape as Claude Code's mcpServers; suffix
		// matching catches both user (~/.kiro/) and project (<repo>/.kiro/) forms.
		{Name: "kiro_mcp", Patterns: []string{".kiro/settings/mcp.json"}, Type: "glob"},

		// Salesforce CLIs. .sf is the newer CLI's auth store;
		// .sfdx/auth/* is the legacy layout. Both hold OAuth refresh tokens.
		{Name: "sf_config", Patterns: []string{".sf/*"}, Type: "glob"},
		{Name: "sfdx_config", Patterns: []string{".sfdx/*", ".sfdx/auth/*"}, Type: "glob"},

		// Ansible — top-level files (galaxy_token, vault_password*).
		// The cp/ socket dir and tmp/ subdirs aren't credentials and
		// produce no findings on a registry pass.
		{Name: "ansible_config", Patterns: []string{".ansible/*"}, Type: "glob"},

		// Rails / WordPress DB config — project-level files holding
		// cleartext DB passwords. Suffix matching catches them at any
		// repo depth without anchoring to home root.
		{Name: "rails_database_yml", Patterns: []string{"config/database.yml"}, Type: "glob"},
		{Name: "wp_config", Patterns: []string{"wp-config.php"}, Type: "glob"},

		// Docker
		{Name: "docker_config", Patterns: []string{".docker/config.json"}, Type: "glob"},

		// Podman / containers — same schema as docker config.json, different path.
		{Name: "podman_config", Patterns: []string{".config/containers/auth.json"}, Type: "glob"},

		// Helm OCI registry auth — `helm registry login` writes a
		// docker-config-shaped JSON here. Same `auths{<host>.auth}`
		// blob with base64(user:password) that DockerProbe already knows how to parse.
		{Name: "helm_oci_registry", Patterns: []string{".config/helm/registry/config.json"}, Type: "glob"},

		// Docker context TLS material — client cert + key + CA for
		// connecting to a remote Docker daemon. Only the key.pem is a
		// secret; cert.pem and ca.pem start with `BEGIN CERTIFICATE`
		// which the SSH-private-key detector ignores by design.
		{Name: "docker_context_keys", Patterns: []string{".docker/contexts/tls/*/*/*.pem"}, Type: "glob"},

		// Kubernetes
		{Name: "kubeconfig", Patterns: []string{".kube/config"}, Type: "glob"},

		// Shell configs
		{Name: "bashrc", Patterns: []string{".bashrc", ".bash_profile", ".profile"}, Type: "glob"},
		{Name: "zshrc", Patterns: []string{".zshrc", ".zprofile"}, Type: "glob"},

		// Shell history files - Unix shells and PowerShell (Windows).
		// Also covers DB and language-REPL input history.
		{Name: "shell_history", Patterns: []string{
			".bash_history",
			".zsh_history",
			".sh_history",
			".history",
			".local/share/fish/fish_history",
			// PowerShell history (Windows)
			"AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
			// DB / language REPL histories
			".psql_history",
			".mysql_history",
			".sqlite_history",
			".python_history",
			".node_repl_history",
			".irb_history",
		}, Type: "glob"},

		// Environment files
		{Name: "env_files", Patterns: []string{".env", ".env.*"}, Type: "glob"},

		// JetBrains
		{Name: "jetbrains", Patterns: []string{".idea/workspace.xml"}, Type: "glob"},

		// AI tools
		{Name: "gemini_credentials", Patterns: []string{".gemini/oauth_creds.json"}, Type: "glob"},
		{Name: "codex_credentials", Patterns: []string{".codex/auth.json"}, Type: "glob"},
		{Name: "opencode_credentials", Patterns: []string{".local/share/opencode/auth.json"}, Type: "glob"},

		{Name: "gemini_chats", Patterns: []string{".gemini/tmp/*/chats/*.json"}, Type: "glob"},
		{Name: "codex_chats", Patterns: []string{".codex/sessions/*/*/*/rollout-*.jsonl"}, Type: "glob"},
		{Name: "claude_chats", Patterns: []string{".claude/projects/*/*.jsonl"}, Type: "glob"},
		{Name: "opencode_chats", Patterns: []string{".local/share/opencode/storage/part/msg_*/prt_*.json"}, Type: "glob"},

		// Additional AI agent history / paste / env surfaces beyond
		// session rollouts. Users routinely paste tokens into prompts;
		// the paste-cache is literally a record of those pastes. REPL
		// history files capture every prompt the user submitted at the
		// top level (separate from per-session rollouts).
		{Name: "claude_repl_history", Patterns: []string{".claude/history.jsonl"}, Type: "glob"},
		{Name: "claude_paste_cache", Patterns: []string{".claude/paste-cache/*"}, Type: "glob"},
		{Name: "claude_session_env", Patterns: []string{".claude/session-env/*"}, Type: "glob"},
		{Name: "codex_repl_history", Patterns: []string{".codex/history.jsonl"}, Type: "glob"},
		{Name: "opencode_session_info", Patterns: []string{".local/share/opencode/storage/session/info/*.json"}, Type: "glob"},
		{Name: "opencode_session_message", Patterns: []string{".local/share/opencode/storage/session/message/*/*.json"}, Type: "glob"},

		// AI agent MCP server configs. mcpServers blocks carry the env
		// map that holds API tokens for third-party services (GitHub
		// PATs, Slack tokens, etc.). claude.json is the application
		// state file; settings.{,local.}json may carry mcpServers too;
		// .mcp.json is a project-level MCP-only file.
		{Name: "claude_app_state", Patterns: []string{".claude/claude.json"}, Type: "glob"},
		{Name: "claude_settings", Patterns: []string{
			".claude/settings.json",
			".claude/settings.local.json",
		}, Type: "glob"},
		{Name: "mcp_project_config", Patterns: []string{".mcp.json"}, Type: "glob"},

		// AI agent context/memory files — pasted secrets get baked
		// into these by users. Basename match: catch them anywhere
		// under home (per-repo CLAUDE.md, global ~/.claude/CLAUDE.md,
		// codex/opencode AGENTS.md, etc.).
		{Name: "ai_memory_md", Patterns: []string{
			"CLAUDE.md",
			"AGENTS.md",
		}, Type: "glob"},

		// Claude Code user-level customization. Commands, agents, and
		// skills are user-authored Markdown that Claude loads as
		// context — secrets in the prompt body get sent to the model
		// on every invocation.
		{Name: "claude_commands", Patterns: []string{".claude/commands/*.md"}, Type: "glob"},
		{Name: "claude_agents", Patterns: []string{".claude/agents/*.md"}, Type: "glob"},
		// Skills usually have SKILL.md at the skill root plus optional
		// sibling .md docs; the glob catches both shapes.
		{Name: "claude_skills", Patterns: []string{".claude/skills/*/*.md"}, Type: "glob"},
		// Cross-agent skill store (a number of plugins symlink into
		// ~/.agents/skills/). Worth scanning so the underlying files
		// surface even when symlinks aren't being followed.
		{Name: "agents_skills", Patterns: []string{".agents/skills/*/*.md"}, Type: "glob"},

		// Codex CLI context/memory.
		{Name: "codex_instructions", Patterns: []string{".codex/instructions.md"}, Type: "glob"},
		{Name: "codex_memories", Patterns: []string{".codex/memories/*"}, Type: "glob"},
		{Name: "codex_skills", Patterns: []string{".codex/skills/*/*.md"}, Type: "glob"},

		// WireGuard (user-level configs; system paths are checked directly by the probe)
		{Name: "wireguard_config", Patterns: []string{".config/wireguard/*.conf"}, Type: "glob"},

		// HashiCorp Vault
		{Name: "vault_token", Patterns: []string{".vault-token"}, Type: "glob"},

		// PyPI
		{Name: "pypirc", Patterns: []string{".pypirc"}, Type: "glob"},
		{Name: "pip_config", Patterns: []string{
			".pip/pip.conf",
			".config/pip/pip.conf",
			// macOS
			"Library/Application Support/pip/pip.conf",
			// Windows
			"AppData/Roaming/pip/pip.ini",
		}, Type: "glob"},

		// Terraform — credentials live in either path. The JSON form is
		// authoritative for `terraform login`; the legacy HCL form is
		// still common from manual setups.
		{Name: "terraform_credentials", Patterns: []string{
			".terraform.d/credentials.tfrc.json",
			".terraformrc",
		}, Type: "glob"},
		// Terraform variable / state files. tfvars commonly hold cloud
		// creds and DB passwords; local-backend state serializes resource
		// outputs (including sensitive ones) as plaintext JSON.
		{Name: "terraform_vars", Patterns: []string{
			"*.tfvars",
			"*.auto.tfvars",
		}, Type: "glob"},
		{Name: "terraform_state", Patterns: []string{
			"terraform.tfstate",
			"terraform.tfstate.backup",
		}, Type: "glob"},

		// Helm — username/password live under repositories[] in this file.
		{Name: "helm_repositories", Patterns: []string{
			".config/helm/repositories.yaml",
			// macOS
			"Library/Preferences/helm/repositories.yaml",
		}, Type: "glob"},
	}
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
