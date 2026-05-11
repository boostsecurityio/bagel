// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package models

// Config represents the Bagel configuration
type Config struct {
	Version     int               `yaml:"version" mapstructure:"version"`
	Probes      ProbeConfig       `yaml:"probes" mapstructure:"probes"`
	Privacy     PrivacyConfig     `yaml:"privacy" mapstructure:"privacy"`
	Output      OutputConfig      `yaml:"output" mapstructure:"output"`
	SeverityMap map[string]string `yaml:"severity_map" mapstructure:"severity_map"`
	FileIndex   FileIndexConfig   `yaml:"file_index" mapstructure:"file_index"`
	HostInfo    HostInfoConfig    `yaml:"hostinfo" mapstructure:"hostinfo"`
	Resources   ResourcesConfig   `yaml:"resources" mapstructure:"resources"`
}

// ResourcesConfig caps bagel's resource usage so callers running it as a
// daemon can dial back its CPU / goroutine footprint. Every field left at
// its zero value preserves the current (unthrottled) behavior.
type ResourcesConfig struct {
	FileIndexWorkers    int    `yaml:"file_index_workers" mapstructure:"file_index_workers"`       // fastwalk workers; 0 = library default
	MaxConcurrentProbes int    `yaml:"max_concurrent_probes" mapstructure:"max_concurrent_probes"` // cap parallel probe execution; 0 = unbounded
	ProbeTimeout        string `yaml:"probe_timeout" mapstructure:"probe_timeout"`                 // per-probe deadline; empty = 30s
}

// HostInfoConfig contains configuration for extended host information collection
type HostInfoConfig struct {
	Extended bool `yaml:"extended" mapstructure:"extended"`
}

// ProbeConfig contains configuration for all probes
type ProbeConfig struct {
	Git           ProbeSettings `yaml:"git" mapstructure:"git"`
	SSH           ProbeSettings `yaml:"ssh" mapstructure:"ssh"`
	NPM           ProbeSettings `yaml:"npm" mapstructure:"npm"`
	Env           ProbeSettings `yaml:"env" mapstructure:"env"`
	ShellHistory  ProbeSettings `yaml:"shell_history" mapstructure:"shell_history"`
	Cloud         ProbeSettings `yaml:"cloud" mapstructure:"cloud"`
	JetBrains     ProbeSettings `yaml:"jetbrains" mapstructure:"jetbrains"`
	GH            ProbeSettings `yaml:"gh" mapstructure:"gh"`
	AICredentials ProbeSettings `yaml:"ai_credentials" mapstructure:"ai_credentials"`
	AIChats       ProbeSettings `yaml:"ai_chats" mapstructure:"ai_chats"`
	WireGuard     ProbeSettings `yaml:"wireguard" mapstructure:"wireguard"`
	PyPI          ProbeSettings `yaml:"pypi" mapstructure:"pypi"`
}

// ProbeSettings contains settings for a specific probe
type ProbeSettings struct {
	Enabled bool                   `yaml:"enabled" mapstructure:"enabled"`
	Flags   map[string]interface{} `yaml:"flags" mapstructure:"flags"`
}

// PrivacyConfig contains privacy-related settings
type PrivacyConfig struct {
	RedactPaths        []string `yaml:"redact_paths" mapstructure:"redact_paths"`
	ExcludeEnvPrefixes []string `yaml:"exclude_env_prefixes" mapstructure:"exclude_env_prefixes"`
}

// OutputConfig contains output-related settings
type OutputConfig struct {
	IncludeFileHashes  bool `yaml:"include_file_hashes" mapstructure:"include_file_hashes"`
	IncludeFileContent bool `yaml:"include_file_content" mapstructure:"include_file_content"`
}

// FileIndexConfig contains configuration for file indexing
type FileIndexConfig struct {
	MaxDepth       int             `yaml:"max_depth" mapstructure:"max_depth"`
	FollowSymlinks bool            `yaml:"follow_symlinks" mapstructure:"follow_symlinks"`
	BaseDirs       []string        `yaml:"base_dirs" mapstructure:"base_dirs"`
	ExcludePaths   []string        `yaml:"exclude_paths" mapstructure:"exclude_paths"`
	Patterns       []PatternConfig `yaml:"patterns" mapstructure:"patterns"`
	Cache          CacheConfig     `yaml:"cache" mapstructure:"cache"`
}

// CacheConfig contains configuration for file index cache staleness detection
type CacheConfig struct {
	TTL            string `yaml:"ttl" mapstructure:"ttl"`                           // Duration string, e.g., "30m"
	SampleSize     int    `yaml:"sample_size" mapstructure:"sample_size"`           // Number of files to sample for validation
	ValidateOnLoad bool   `yaml:"validate_on_load" mapstructure:"validate_on_load"` // Enable staleness checking
}

// PatternConfig defines a file pattern to index
type PatternConfig struct {
	Name     string   `yaml:"name" mapstructure:"name"`
	Patterns []string `yaml:"patterns" mapstructure:"patterns"`
	Type     string   `yaml:"type" mapstructure:"type"` // "glob", "exact", "regex"
}
