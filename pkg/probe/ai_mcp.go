// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// defaultMCPMaxFileSize caps each MCP-config read. claude.json grows
// large with project history; settings files stay tiny. 4 MB is enough
// for realistic claude.json sizes while still bounding JSON decode.
const defaultMCPMaxFileSize = 4 * 1024 * 1024

// MCPProbe extracts credentials embedded in Model Context Protocol
// server configurations. MCP servers are launched as subprocesses by
// AI agents (Claude Code, OpenCode, Codex, etc.); their config blocks
// hold a `command`, `args`, and `env` map that the agent forwards to
// the spawned process. The `env` map routinely contains third-party
// API tokens — GitHub PATs, Slack tokens, DB connection strings — in
// cleartext, which makes it one of the highest-value AI-side
// credential sources today.
//
// Scan-only: never registered in scrub. Replacing real tokens in these
// files with redaction markers would silently break the MCP server's
// authentication when the agent next launches it.
type MCPProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
}

// NewMCPProbe creates the AI MCP probe.
func NewMCPProbe(config models.ProbeSettings, registry *detector.Registry) *MCPProbe {
	return &MCPProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultMCPMaxFileSize),
	}
}

// Name returns the probe name.
func (p *MCPProbe) Name() string { return "ai_mcp" }

// IsEnabled returns whether the probe is enabled.
func (p *MCPProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *MCPProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *MCPProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// mcpConfigPatterns lists the file-index pattern names whose matches
// contain MCP server config. Claude Code splits configs across
// claude.json, settings.{,local.}json, and .mcp.json; Kiro IDE uses
// its own .kiro/settings/mcp.json. All share the same `mcpServers`
// JSON schema, so the same parser handles every entry.
var mcpConfigPatterns = []string{
	"claude_app_state",   // ~/.claude/claude.json
	"claude_settings",    // ~/.claude/settings{,.local}.json + project .claude/settings.local.json
	"mcp_project_config", // project .mcp.json
	"kiro_mcp",           // ~/.kiro/settings/mcp.json + project .kiro/settings/mcp.json
}

// Execute walks every indexed MCP config file and emits findings for
// credentials it carries.
func (p *MCPProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping ai_mcp probe")
		return nil, nil
	}

	seen := make(map[string]struct{})
	var findings []models.Finding
	for _, pattern := range mcpConfigPatterns {
		for _, path := range p.fileIndex.Get(pattern) {
			if _, dup := seen[path]; dup {
				continue
			}
			seen[path] = struct{}{}
			findings = append(findings, p.processConfig(ctx, path)...)
		}
	}
	return findings, nil
}

// mcpServerEntry is the minimum subset of an MCP server config we need
// to reach credential-bearing fields. Other fields (`type`, `disabled`,
// `cwd`, etc.) don't carry secrets and are intentionally ignored.
type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	// Some Claude Code variants used `envVars` historically; accept it
	// too so credentials defined that way still surface.
	EnvVars map[string]string `json:"envVars"`
}

// mcpConfigDoc captures only the mcpServers map. claude.json carries
// many other top-level keys (state, telemetry, etc.) — we ignore them.
type mcpConfigDoc struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

// processConfig reads one MCP config file, parses it, and emits a
// finding per credential the registry detects in env values or args.
func (p *MCPProbe) processConfig(ctx context.Context, path string) []models.Finding {
	info, err := os.Stat(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot stat MCP config")
		return nil
	}
	if info.Size() > p.maxFileSize {
		log.Ctx(ctx).Debug().
			Str("file", path).
			Int64("size_bytes", info.Size()).
			Int64("max_size_bytes", p.maxFileSize).
			Msg("Skipping oversized MCP config")
		return nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot read MCP config")
		return nil
	}

	var doc mcpConfigDoc
	if err := json.Unmarshal(content, &doc); err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot parse MCP config JSON")
		return nil
	}

	var findings []models.Finding
	for name, server := range doc.MCPServers {
		findings = append(findings, p.scanServerEnv(path, name, server)...)
		findings = append(findings, p.scanServerArgs(path, name, server)...)
	}
	return findings
}

// scanServerEnv feeds every env value (and the legacy envVars map)
// through the detector registry. Each detected credential carries
// metadata locating it back to mcpServers["<name>"].<map>["<key>"] —
// preserving which map (env vs envVars) the value came from, so users
// rotate the right key.
func (p *MCPProbe) scanServerEnv(path, serverName string, server mcpServerEntry) []models.Finding {
	var findings []models.Finding
	for _, src := range []struct {
		mapKey string
		envMap map[string]string
	}{
		{"env", server.Env},
		{"envVars", server.EnvVars},
	} {
		for envKey, envVal := range src.envMap {
			if envVal == "" {
				continue
			}
			location := fmt.Sprintf("mcpServers[%q].%s[%q]", serverName, src.mapKey, envKey)
			detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
				Source:    "file:" + path,
				ProbeName: p.Name(),
			})
			for _, f := range p.detectorRegistry.DetectAll(envVal, detCtx) {
				p.annotate(&f, path, serverName, server.Command, location, envKey)
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// pkgRunners are the command names whose first non-flag arg is the
// package identifier itself (e.g. `npx -y @scope/pkg ...`). We skip
// that one arg through the registry because scope/package names look
// suspicious to the generic-api-key detector.
var pkgRunners = map[string]struct{}{
	"npx":  {},
	"bunx": {},
	"uvx":  {},
}

// looksLikePackageIdent is a deliberately tight guard: we only skip an
// arg if it's clearly a scoped npm package (`@scope/name[@version]`),
// which is the dominant MCP-server publishing shape today. Unscoped
// names ("mcp-server-foo") are short and low-entropy enough that
// downstream detectors don't false-positive on them — and skipping
// would risk silently dropping a real credential that happens to land
// at the first non-flag arg.
func looksLikePackageIdent(s string) bool {
	if !strings.HasPrefix(s, "@") || !strings.Contains(s, "/") {
		return false
	}
	// The slash must come after the scope, not at the end.
	slash := strings.IndexByte(s, '/')
	if slash <= 1 || slash == len(s)-1 {
		return false
	}
	return true
}

// scanServerArgs feeds args strings through the registry. Some MCP
// packages take the credential on the command line (e.g.
// `npx -y @vendor/server --api-key XYZ`), so this catches the case
// where the env-map path doesn't.
func (p *MCPProbe) scanServerArgs(path, serverName string, server mcpServerEntry) []models.Finding {
	var findings []models.Finding

	// Compute the index of the first non-flag arg up front so the loop
	// body stays a single pass. For pkgRunner commands, that arg is the
	// package identifier and we skip it (only if it actually looks like
	// one — otherwise we'd silently drop a real credential).
	skipIdx := -1
	if _, isRunner := pkgRunners[server.Command]; isRunner {
		for i, a := range server.Args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if looksLikePackageIdent(a) {
				skipIdx = i
			}
			break
		}
	}

	for i, arg := range server.Args {
		if arg == "" || i == skipIdx {
			continue
		}
		location := fmt.Sprintf("mcpServers[%q].args[%d]", serverName, i)
		detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
			Source:    "file:" + path,
			ProbeName: p.Name(),
		})
		for _, f := range p.detectorRegistry.DetectAll(arg, detCtx) {
			p.annotate(&f, path, serverName, server.Command, location, "")
			findings = append(findings, f)
		}
	}
	return findings
}

// annotate attaches the MCP-server context (which server, which
// command, where in the file) to a registry finding so users can map
// the credential back to the agent that's using it.
func (p *MCPProbe) annotate(
	f *models.Finding,
	path, serverName, serverCommand, location, envKey string,
) {
	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}
	f.Metadata["mcp_server_name"] = serverName
	if serverCommand != "" {
		f.Metadata["mcp_server_command"] = serverCommand
	}
	f.Metadata["location"] = location
	if envKey != "" {
		f.Metadata["env_var"] = envKey
	}
	// Override Path so the terminal-clickable location points at the
	// MCP config file itself, not at any synthetic source the registry
	// might have set.
	f.Path = "file:" + path
	// Keep registry findings recognizable as belonging to this probe.
	f.Probe = p.Name()
	// Trim trailing whitespace from Message to keep table output tidy.
	f.Message = strings.TrimSpace(f.Message)
}
