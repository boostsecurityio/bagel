// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
)

// MiseProbe scans mise (https://mise.jdx.dev) configuration files
// for plaintext secrets in [env] tables, [[env]] array-of-tables,
// and inline [tasks.*] env/run blocks. The `redact = true` table
// form only suppresses values from `mise env` output at runtime -
// the secret sits in plaintext on disk and is read by every shell
// that activates mise.
//
// File coverage tracks mise's own LOCAL_CONFIG_FILENAMES list (see
// src/config/mod.rs in jdx/mise) plus the env-specific variants
// from DEFAULT_CONFIG_FILENAMES. classifyMiseFile tags each
// discovered file with its role (global vs project, local-override,
// env-specific, conf.d fragment, legacy rtx).
//
// File-task scripts under mise-tasks/, .mise-tasks/, mise/tasks/,
// .mise/tasks/, .config/mise/tasks/ are handled by MiseTasksProbe.
//
// Finding metadata keys emitted:
//
//	mise_env_var       string  - env var name (structured walks only)
//	mise_redact_flag   bool    - value carried `redact = true`
//	mise_task_name     string  - task name (when in [tasks.<name>])
//	mise_task_field    string  - "env" or "run"
//	mise_file_kind     string  - "global" | "project" | "system"
//	mise_file_local    bool    - filename ends with .local.toml
//	mise_file_legacy   bool    - .rtx.* family
//	mise_file_fragment bool    - under a conf.d/ directory
//	mise_file          string  - basename of the config file
//	mise_file_env      string  - MISE_ENV scope from filename
//
// Boolean keys are omitted when false to keep JSON output compact.
type MiseProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
	userHome         string
	userAppData      string
}

// NewMiseProbe creates the mise config probe. Accepts an optional
// "max_file_size" flag (int / int64 / float64, bytes) overriding
// the default 4 MB read cap.
func NewMiseProbe(config models.ProbeSettings, registry *detector.Registry) *MiseProbe {
	home, appData := resolveMiseUserDirs()
	return &MiseProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultMiseMaxFileSize),
		userHome:         home,
		userAppData:      appData,
	}
}

// Name returns the probe name.
func (p *MiseProbe) Name() string { return "mise" }

// IsEnabled returns whether the probe is enabled.
func (p *MiseProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *MiseProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *MiseProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute walks every indexed mise config file. Honours context
// cancellation between files so a slow walk on a large monorepo
// can be aborted promptly.
func (p *MiseProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().Str("probe", p.Name()).Msg("File index not available, skipping mise probe")
		return nil, nil
	}
	paths := p.fileIndex.Get("mise_config")
	log.Ctx(ctx).Debug().Int("mise_config_count", len(paths)).Msg("Found mise config files")

	var findings []models.Finding
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return findings, fmt.Errorf("mise probe canceled: %w", err)
		}
		findings = append(findings, p.processFile(ctx, path)...)
	}
	return findings, nil
}

// processFile runs the structured TOML walk and the line-scan
// safety net against `path`, dedup'ing line-scan findings whose
// fingerprint already appears in the structured set. Internal
// dedup keeps the metadata-richer structured finding even when
// cross-probe reporter ordering would otherwise drop it.
func (p *MiseProbe) processFile(ctx context.Context, path string) []models.Finding {
	content := readBoundedMiseFile(ctx, p.Name(), path, p.maxFileSize)
	if content == nil {
		return nil
	}

	scan := miseScanCtx{
		registry:  p.detectorRegistry,
		probeName: p.Name(),
		path:      path,
		class:     classifyMiseFile(path, p.userHome, p.userAppData),
	}

	structured := p.scanStructured(ctx, content, scan)
	findings := append(make([]models.Finding, 0, len(structured)+2), structured...)

	seen := make(map[string]struct{}, len(structured))
	for _, f := range structured {
		if f.Fingerprint != "" {
			seen[f.Fingerprint] = struct{}{}
		}
	}
	// Pass `0` so scanReaderLines uses its safe default (1 MB per
	// line). The 4MB file cap bounds total bytes; the per-line cap
	// bounds regex slot size against adversarial single-line input.
	for _, f := range scanReaderLines(ctx, "file:"+path, bytes.NewReader(content), p.Name(), p.detectorRegistry, 0) {
		if _, dup := seen[f.Fingerprint]; dup {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}

// scanStructured parses the TOML and walks every [env] and
// [tasks.*] table. Failures to parse return nil; the line-scan
// pass in the caller still runs.
//
// Top-level [env] shapes supported:
//
//	[env]    - table       - doc["env"] is map[string]any
//	[[env]]  - array       - doc["env"] is []any of maps (used to
//	                         group multiple env._.source directives)
//
// [tasks] shape: trivial form `tasks.<name> = "command"` and
// detailed form `tasks.<name> = { env = {...}, run = "..." | [...], ... }`.
func (p *MiseProbe) scanStructured(ctx context.Context, content []byte, scan miseScanCtx) []models.Finding {
	doc, ok := p.decodeTOML(ctx, content, scan.path)
	if !ok {
		return nil
	}
	var findings []models.Finding
	switch e := doc["env"].(type) {
	case map[string]any:
		findings = append(findings, scan.scanEnvTable(e, "")...)
	case []any:
		for _, item := range e {
			if m, ok := item.(map[string]any); ok {
				findings = append(findings, scan.scanEnvTable(m, "")...)
			}
		}
	}
	if tasks, ok := doc["tasks"].(map[string]any); ok {
		findings = append(findings, p.scanTasksTable(tasks, scan)...)
	}
	return findings
}

// decodeTOML wraps toml.Unmarshal in a recover() so a parser panic
// on adversarial input (deeply nested tables, malformed structures
// that trigger a future parser bug) is contained per file. The
// caller's line-scan pass still runs on the raw bytes regardless.
func (p *MiseProbe) decodeTOML(ctx context.Context, content []byte, path string) (doc map[string]any, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Ctx(ctx).Debug().Str("file", path).Interface("panic", r).Msg("Recovered from panic in mise TOML decoder")
			doc, ok = nil, false
		}
	}()
	if err := toml.Unmarshal(content, &doc); err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("file", path).Msg("Cannot parse mise TOML")
		return nil, false
	}
	return doc, doc != nil
}

// scanTasksTable walks a [tasks] table. The probe scans:
//
//	tasks.<name>.env  - same shape as top-level [env]
//	tasks.<name>.run  - string or array of strings
//	tasks.<name>      - bare string (trivial form, treated as run)
//
// Other fields (description, depends, sources, outputs, alias,
// dir, shell, file, usage, ...) are not secret-bearing and skipped.
func (p *MiseProbe) scanTasksTable(tasks map[string]any, scan miseScanCtx) []models.Finding {
	var findings []models.Finding
	for name, raw := range tasks {
		switch v := raw.(type) {
		case string:
			findings = append(findings, p.scanTaskRun(name, v, scan)...)
		case map[string]any:
			if env, ok := v["env"].(map[string]any); ok {
				findings = append(findings, scan.scanEnvTable(env, name)...)
			}
			switch run := v["run"].(type) {
			case string:
				findings = append(findings, p.scanTaskRun(name, run, scan)...)
			case []any:
				for _, item := range run {
					if s, ok := item.(string); ok {
						findings = append(findings, p.scanTaskRun(name, s, scan)...)
					}
				}
			}
		}
	}
	return findings
}

// scanTaskRun runs the detector registry over a task's run string
// (or one element of a run array, or the value of a trivial
// string-form task) and tags findings with the task name.
func (p *MiseProbe) scanTaskRun(taskName, run string, scan miseScanCtx) []models.Finding {
	if scan.registry == nil || run == "" {
		return nil
	}
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + scan.path,
		ProbeName: scan.probeName,
	})
	raw := scan.registry.DetectAll(run, detCtx)
	if len(raw) == 0 {
		return nil
	}
	findings := make([]models.Finding, 0, len(raw))
	for _, f := range raw {
		if f.Metadata == nil {
			f.Metadata = make(map[string]interface{})
		}
		f.Probe = scan.probeName
		f.Path = "file:" + scan.path
		f.Metadata["mise_task_name"] = taskName
		f.Metadata["mise_task_field"] = "run"
		f.Metadata["mise_file_kind"] = scan.class.Kind
		f.Metadata["mise_file"] = filepath.Base(scan.path)
		if scan.class.IsLocal {
			f.Metadata["mise_file_local"] = true
		}
		if scan.class.IsLegacy {
			f.Metadata["mise_file_legacy"] = true
		}
		if scan.class.IsFragment {
			f.Metadata["mise_file_fragment"] = true
		}
		if scan.class.EnvName != "" {
			f.Metadata["mise_file_env"] = scan.class.EnvName
		}
		f.Message = fmt.Sprintf("In file:%s: task %q `run` contains a detected secret", scan.path, taskName)
		findings = append(findings, f)
	}
	return findings
}
