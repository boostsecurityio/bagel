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
		{"name": "aws_sso_cache", "patterns": []string{".aws/sso/cache/*.json"}, "type": "glob"},
		{"name": "aws_cli_cache", "patterns": []string{".aws/cli/cache/*.json"}, "type": "glob"},

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
		{"name": "azure_tokens", "patterns": []string{
			".azure/accessTokens.json",
			".azure/msal_token_cache.*",
			".azure/msazure.login/*",
			".azure/azd/*",
			"AppData/Roaming/.azure/accessTokens.json",
			"AppData/Roaming/.azure/msal_token_cache.*",
		}, "type": "glob"},
		{"name": "oci_config", "patterns": []string{
			".oci/config",
			".oci/sessions/*",
		}, "type": "glob"},
		{"name": "aliyun_config", "patterns": []string{".aliyun/config.json"}, "type": "glob"},
		{"name": "bluemix_config", "patterns": []string{".bluemix/config.json"}, "type": "glob"},
		{"name": "doctl_config", "patterns": []string{".config/doctl/config.yaml"}, "type": "glob"},
		{"name": "hcloud_config", "patterns": []string{".config/hcloud/cli.toml"}, "type": "glob"},
		{"name": "scw_config", "patterns": []string{".config/scw/config.yaml"}, "type": "glob"},
		{"name": "linode_config", "patterns": []string{".config/linode-cli/*"}, "type": "glob"},
		{"name": "fly_config", "patterns": []string{".fly/config.yml"}, "type": "glob"},
		{"name": "vercel_config", "patterns": []string{".vercel/auth.json"}, "type": "glob"},
		{"name": "railway_config", "patterns": []string{".railway/config.json"}, "type": "glob"},
		{"name": "snowflake_config", "patterns": []string{".snowflake/connections.toml"}, "type": "glob"},
		{"name": "doppler_config", "patterns": []string{".doppler.yaml"}, "type": "glob"},
		{"name": "gh_hosts", "patterns": []string{".config/gh/hosts.yml"}, "type": "glob"},
		{"name": "glab_config", "patterns": []string{".config/glab-cli/config.yml"}, "type": "glob"},
		{"name": "hub_config", "patterns": []string{".config/hub"}, "type": "glob"},
		{"name": "netrc_file", "patterns": []string{".netrc", "_netrc"}, "type": "glob"},

		// Kiro IDE MCP — same shape as Claude Code's mcpServers; suffix
		// matching catches both user (~/.kiro/) and project (<repo>/.kiro/) forms.
		{"name": "kiro_mcp", "patterns": []string{".kiro/settings/mcp.json"}, "type": "glob"},

		// Salesforce CLIs. .sf is the newer CLI's auth store;
		// .sfdx/auth/* is the legacy layout. Both hold OAuth refresh tokens.
		{"name": "sf_config", "patterns": []string{".sf/*"}, "type": "glob"},
		{"name": "sfdx_config", "patterns": []string{".sfdx/*", ".sfdx/auth/*"}, "type": "glob"},

		// Ansible — top-level files (galaxy_token, vault_password*).
		// The cp/ socket dir and tmp/ subdirs aren't credentials and
		// produce no findings on a registry pass.
		{"name": "ansible_config", "patterns": []string{".ansible/*"}, "type": "glob"},

		// Rails / WordPress DB config — project-level files holding
		// cleartext DB passwords. Suffix matching catches them at any
		// repo depth without anchoring to home root.
		{"name": "rails_database_yml", "patterns": []string{"config/database.yml"}, "type": "glob"},
		{"name": "wp_config", "patterns": []string{"wp-config.php"}, "type": "glob"},

		// Docker
		{"name": "docker_config", "patterns": []string{".docker/config.json"}, "type": "glob"},

		// Podman / containers — same schema as docker config.json, different path.
		{"name": "podman_config", "patterns": []string{".config/containers/auth.json"}, "type": "glob"},

		// Helm OCI registry auth — `helm registry login` writes a
		// docker-config-shaped JSON here. Same `auths{<host>.auth}`
		// blob with base64(user:password) that DockerProbe already knows how to parse.
		{"name": "helm_oci_registry", "patterns": []string{".config/helm/registry/config.json"}, "type": "glob"},

		// Docker context TLS material — client cert + key + CA for
		// connecting to a remote Docker daemon. Only the key.pem is a
		// secret; cert.pem and ca.pem start with `BEGIN CERTIFICATE`
		// which the SSH-private-key detector ignores by design.
		{"name": "docker_context_keys", "patterns": []string{".docker/contexts/tls/*/*/*.pem"}, "type": "glob"},

		// Kubernetes
		{"name": "kubeconfig", "patterns": []string{".kube/config"}, "type": "glob"},

		// Shell configs
		{"name": "bashrc", "patterns": []string{".bashrc", ".bash_profile", ".profile"}, "type": "glob"},
		{"name": "zshrc", "patterns": []string{".zshrc", ".zprofile"}, "type": "glob"},

		// Shell history files - Unix shells and PowerShell (Windows).
		// Also covers DB and language-REPL input history.
		{"name": "shell_history", "patterns": []string{
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

		// Additional AI agent history / paste / env surfaces beyond
		// session rollouts. Users routinely paste tokens into prompts;
		// the paste-cache is literally a record of those pastes. REPL
		// history files capture every prompt the user submitted at the
		// top level (separate from per-session rollouts).
		{"name": "claude_repl_history", "patterns": []string{".claude/history.jsonl"}, "type": "glob"},
		{"name": "claude_paste_cache", "patterns": []string{".claude/paste-cache/*"}, "type": "glob"},
		{"name": "claude_session_env", "patterns": []string{".claude/session-env/*"}, "type": "glob"},
		{"name": "codex_repl_history", "patterns": []string{".codex/history.jsonl"}, "type": "glob"},
		{"name": "opencode_session_info", "patterns": []string{".local/share/opencode/storage/session/info/*.json"}, "type": "glob"},
		{"name": "opencode_session_message", "patterns": []string{".local/share/opencode/storage/session/message/*/*.json"}, "type": "glob"},

		// AI agent MCP server configs. mcpServers blocks carry the env
		// map that holds API tokens for third-party services (GitHub
		// PATs, Slack tokens, etc.). claude.json is the application
		// state file; settings.{,local.}json may carry mcpServers too;
		// .mcp.json is a project-level MCP-only file.
		{"name": "claude_app_state", "patterns": []string{".claude/claude.json"}, "type": "glob"},
		{"name": "claude_settings", "patterns": []string{
			".claude/settings.json",
			".claude/settings.local.json",
		}, "type": "glob"},
		{"name": "mcp_project_config", "patterns": []string{".mcp.json"}, "type": "glob"},

		// AI agent context/memory files — pasted secrets get baked
		// into these by users. Basename match: catch them anywhere
		// under home (per-repo CLAUDE.md, global ~/.claude/CLAUDE.md,
		// codex/opencode AGENTS.md, etc.).
		{"name": "ai_memory_md", "patterns": []string{
			"CLAUDE.md",
			"AGENTS.md",
		}, "type": "glob"},

		// Claude Code user-level customization. Commands, agents, and
		// skills are user-authored Markdown that Claude loads as
		// context — secrets in the prompt body get sent to the model
		// on every invocation.
		{"name": "claude_commands", "patterns": []string{".claude/commands/*.md"}, "type": "glob"},
		{"name": "claude_agents", "patterns": []string{".claude/agents/*.md"}, "type": "glob"},
		// Skills usually have SKILL.md at the skill root plus optional
		// sibling .md docs; the glob catches both shapes.
		{"name": "claude_skills", "patterns": []string{".claude/skills/*/*.md"}, "type": "glob"},
		// Cross-agent skill store (a number of plugins symlink into
		// ~/.agents/skills/). Worth scanning so the underlying files
		// surface even when symlinks aren't being followed.
		{"name": "agents_skills", "patterns": []string{".agents/skills/*/*.md"}, "type": "glob"},

		// Codex CLI context/memory.
		{"name": "codex_instructions", "patterns": []string{".codex/instructions.md"}, "type": "glob"},
		{"name": "codex_memories", "patterns": []string{".codex/memories/*"}, "type": "glob"},
		{"name": "codex_skills", "patterns": []string{".codex/skills/*/*.md"}, "type": "glob"},

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

		// Terraform — credentials live in either path. The JSON form is
		// authoritative for `terraform login`; the legacy HCL form is
		// still common from manual setups.
		{"name": "terraform_credentials", "patterns": []string{
			".terraform.d/credentials.tfrc.json",
			".terraformrc",
		}, "type": "glob"},
		// Terraform variable / state files. tfvars commonly hold cloud
		// creds and DB passwords; local-backend state serializes resource
		// outputs (including sensitive ones) as plaintext JSON.
		{"name": "terraform_vars", "patterns": []string{
			"*.tfvars",
			"*.auto.tfvars",
		}, "type": "glob"},
		{"name": "terraform_state", "patterns": []string{
			"terraform.tfstate",
			"terraform.tfstate.backup",
		}, "type": "glob"},

		// Helm — username/password live under repositories[] in this file.
		{"name": "helm_repositories", "patterns": []string{
			".config/helm/repositories.yaml",
			// macOS
			"Library/Preferences/helm/repositories.yaml",
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
