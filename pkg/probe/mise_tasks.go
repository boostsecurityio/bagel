// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/pelletier/go-toml/v2"
	"github.com/rs/zerolog/log"
)

// MiseTasksProbe scans mise file-task scripts for plaintext
// secrets. File tasks are executable scripts under any of:
//
//	mise-tasks/<name>
//	.mise-tasks/<name>
//	mise/tasks/<name>
//	.mise/tasks/<name>
//	.config/mise/tasks/<name>
//
// Sub-directories are valid - mise composes `test:units` from
// `mise-tasks/test/units`. Scripts can be any interpreter (bash,
// python, node, deno, ...) selected by a shebang, with mise-specific
// configuration in `#MISE`/`# [MISE]`/`//MISE` header comments. The
// `env={...}` header is an inline TOML table.
//
// Two passes:
//
//  1. Header parse - every `#MISE env={...}` directive is decoded as
//     inline TOML and walked through the detector registry.
//     Findings carry mise_task_field=env.
//  2. Line scan - body content is regex-scanned for plaintext
//     secrets (e.g. curl invocations with embedded bearer tokens).
//
// Findings from both passes are dedup'd by fingerprint inside the
// probe so the metadata-richer header finding wins over a line-
// scan duplicate.
type MiseTasksProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
	maxFileSize      int64
	userHome         string
	userAppData      string
}

// NewMiseTasksProbe creates the mise file-tasks probe. Accepts an
// optional "max_file_size" flag (int / int64 / float64, bytes)
// overriding the default 4 MB read cap.
func NewMiseTasksProbe(config models.ProbeSettings, registry *detector.Registry) *MiseTasksProbe {
	home, appData := resolveMiseUserDirs()
	return &MiseTasksProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
		maxFileSize:      readMaxFileSizeFlag(config.Flags, defaultMiseMaxFileSize),
		userHome:         home,
		userAppData:      appData,
	}
}

// Name returns the probe name.
func (p *MiseTasksProbe) Name() string { return "mise_tasks" }

// IsEnabled returns whether the probe is enabled.
func (p *MiseTasksProbe) IsEnabled() bool { return p.enabled }

// SetFingerprintSalt sets the fingerprint salt on the detector registry.
func (p *MiseTasksProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe.
func (p *MiseTasksProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// Execute walks every indexed file-task script.
func (p *MiseTasksProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().Str("probe", p.Name()).Msg("File index not available, skipping mise_tasks probe")
		return nil, nil
	}
	paths := p.fileIndex.Get("mise_task_file")
	log.Ctx(ctx).Debug().Int("mise_task_file_count", len(paths)).Msg("Found mise file-task scripts")

	var findings []models.Finding
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return findings, fmt.Errorf("mise_tasks probe canceled: %w", err)
		}
		findings = append(findings, p.processTaskFile(ctx, path)...)
	}
	return findings, nil
}

func (p *MiseTasksProbe) processTaskFile(ctx context.Context, path string) []models.Finding {
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
	taskName := deriveMiseTaskName(path)

	var findings []models.Finding
	if env := parseMiseTaskHeaderEnv(ctx, content, path); env != nil {
		structured := scan.scanEnvTable(env, taskName)
		for i := range structured {
			structured[i].Metadata["mise_task_file"] = true
		}
		findings = structured
	}

	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if f.Fingerprint != "" {
			seen[f.Fingerprint] = struct{}{}
		}
	}
	for _, f := range scanReaderLines(ctx, "file:"+path, bytes.NewReader(content), p.Name(), p.detectorRegistry, 0) {
		if _, dup := seen[f.Fingerprint]; dup {
			continue
		}
		if f.Metadata == nil {
			f.Metadata = make(map[string]interface{})
		}
		f.Metadata["mise_task_file"] = true
		f.Metadata["mise_task_name"] = taskName
		f.Metadata["mise_file_kind"] = scan.class.Kind
		f.Metadata["mise_file"] = filepath.Base(path)
		findings = append(findings, f)
	}
	return findings
}

// miseTaskRoots is the list of directory markers mise loads file
// tasks from, in the order documented at /tasks/file-tasks.html.
// Each entry is slash-prefixed so it survives intact through
// filepath.ToSlash.
var miseTaskRoots = []string{
	"/mise-tasks/",
	"/.mise-tasks/",
	"/mise/tasks/",
	"/.mise/tasks/",
	"/.config/mise/tasks/",
}

// deriveMiseTaskName converts an absolute file-task path into the
// task name mise itself would assign. Sub-directories become `:`-
// separated components (`mise-tasks/test/units` → `test:units`);
// the special `_default` filename collapses to its containing
// directory (`mise-tasks/test/_default` → `test`). Falls back to
// the basename when no task-root marker is present.
func deriveMiseTaskName(path string) string {
	p := filepath.ToSlash(path)
	for _, root := range miseTaskRoots {
		idx := strings.Index(p, root)
		if idx < 0 {
			continue
		}
		tail := strings.TrimSuffix(p[idx+len(root):], "/_default")
		if tail == "" {
			break
		}
		return strings.ReplaceAll(tail, "/", ":")
	}
	return filepath.Base(path)
}

// miseTaskHeaderEnvRe matches mise task header `env=` directives in
// the four documented spellings:
//
//	#MISE env=...        bash, python, ruby, powershell
//	# [MISE] env=...     formatter-safe alternative
//	//MISE env=...       js, ts, deno, node
//	// [MISE] env=...    formatter-safe js/ts alternative
//
// The capture holds whatever follows `env=` (typically an inline
// TOML table `{...}`); decode happens in parseMiseTaskHeaderEnv.
//
// `# MISE` with a space is intentionally NOT matched - mise itself
// ignores that spelling to avoid formatter rewrites changing
// semantics. The `# [MISE]` form is the documented workaround.
var miseTaskHeaderEnvRe = regexp.MustCompile(
	`(?m)^\s*(?://|#)\s*(?:MISE|\[MISE\])\s+env\s*=\s*(.+?)\s*$`,
)

// parseMiseTaskHeaderEnv scans the script for `#MISE env=...`
// directives and returns the merged env map. Multiple headers
// merge with last-writer-wins (matching mise's own semantics).
// Returns nil when no header is found or none decode.
func parseMiseTaskHeaderEnv(ctx context.Context, content []byte, path string) map[string]any {
	matches := miseTaskHeaderEnvRe.FindAllSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	merged := make(map[string]any)
	for _, m := range matches {
		// Synthesise a `env = <value>` TOML document so the parser
		// handles inline-table escaping for us.
		doc := append([]byte("env = "), m[1]...)
		var parsed map[string]any
		if err := toml.Unmarshal(doc, &parsed); err != nil {
			// Log neither the header value nor the parse error: the
			// value can hold a plaintext secret, and go-toml error
			// messages interpolate the offending input byte (%c/%#U)
			// at the failure offset. bagel never logs secret material,
			// so we record only the file path and the value length.
			log.Ctx(ctx).Debug().Str("file", path).Int("header_bytes", len(m[1])).
				Msg("Cannot parse #MISE env header value as TOML")
			continue
		}
		env, ok := parsed["env"].(map[string]any)
		if !ok {
			continue
		}
		for k, v := range env {
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}
