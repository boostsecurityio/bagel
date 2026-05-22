// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// Shared helpers for the mise (config-file) and mise_tasks (file-
// task script) probes. Both target mise (https://mise.jdx.dev) and
// emit findings with the same `mise_*` metadata vocabulary.

// defaultMiseMaxFileSize caps each mise file read. Mise configs are
// typically <100KB; 4MB matches the IaC probe.
const defaultMiseMaxFileSize = 4 * 1024 * 1024 // 4 MB

// File-kind values emitted in the mise_file_kind metadata field.
const (
	miseFileKindGlobal  = "global"
	miseFileKindProject = "project"
	miseFileKindSystem  = "system"
)

// envNameDenylist holds filename middle segments that look like
// MISE_ENV scopes but aren't (`mise.config.toml`, `mise.backup.toml`).
// Hitting any of these clears EnvName so consumers don't see a
// meaningless environment tag. Add to the list when noisy false
// positives turn up.
var envNameDenylist = map[string]struct{}{
	"config":  {},
	"backup":  {},
	"old":     {},
	"example": {},
	"sample":  {},
	"bak":     {},
	"orig":    {},
}

// miseFileClassification captures the diagnostic role of a mise
// file so consumers can prioritise findings (a leak in the global
// config affects every shell of this user; a leak in
// mise.local.toml is usually gitignored but still readable).
type miseFileClassification struct {
	// Kind is one of miseFileKindGlobal / Project / System.
	Kind string
	// IsLocal is true for `.local.toml` files (gitignore territory).
	IsLocal bool
	// EnvName is the MISE_ENV scope embedded in the filename
	// ("production" for mise.production.toml). Empty for base
	// forms, for conf.d fragments, and for denylisted middle
	// segments.
	EnvName string
	// IsLegacy is true for the pre-rename `.rtx.*` family.
	IsLegacy bool
	// IsFragment is true when the file lives under a `conf.d/`
	// directory; the filename prefix is a sort key, not an env
	// scope.
	IsFragment bool
}

// classifyMiseFile inspects a path and returns its diagnostic role.
// Pure function (no FS access) so tests can drive it with synthetic
// paths. `home` and `appData` are the user's home directory and
// Windows APPDATA respectively; either may be empty (the function
// degrades to a substring heuristic).
func classifyMiseFile(path, home, appData string) miseFileClassification {
	base := filepath.Base(path)
	cls := miseFileClassification{Kind: miseFileKindProject}

	switch {
	case isMiseGlobalPath(path, home, appData):
		cls.Kind = miseFileKindGlobal
	case isMiseSystemPath(path):
		cls.Kind = miseFileKindSystem
	}

	// conf.d fragment detection runs before env-name extraction so a
	// filename like `01-go.toml` doesn't get "01-go" tagged as a
	// MISE_ENV scope.
	if strings.Contains(filepath.ToSlash(path), "/conf.d/") {
		cls.IsFragment = true
	}

	stem := strings.TrimSuffix(base, ".toml")
	if strings.HasPrefix(base, ".rtx.") || base == ".rtx.toml" {
		cls.IsLegacy = true
	}
	if strings.HasSuffix(stem, ".local") {
		cls.IsLocal = true
		stem = strings.TrimSuffix(stem, ".local")
	}

	if cls.IsFragment {
		return cls
	}
	for _, prefix := range []string{"mise.", ".mise.", "config.", ".rtx."} {
		if !strings.HasPrefix(stem, prefix) {
			continue
		}
		rest := strings.TrimPrefix(stem, prefix)
		if rest == "" || !validMiseEnvName(rest) {
			break
		}
		if _, deny := envNameDenylist[rest]; deny {
			break
		}
		cls.EnvName = rest
		break
	}
	return cls
}

// validMiseEnvName reports whether s is plausibly a MISE_ENV value.
// Real env names are alphanumeric with `-`, `_`, or `.` separators
// (e.g. "production", "staging-1", "ci.linux"); anything containing
// whitespace, path separators, or other punctuation almost certainly
// came from a malformed filename and is rejected.
func validMiseEnvName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// isMiseGlobalPath reports whether `path` lives inside the mise
// user-global config directory. Anchored to `home`/`appData` so a
// project-checked-in dotfiles tree at <repo>/.config/mise/ isn't
// misclassified as global. Falls back to a substring heuristic
// when no anchor is available - the kind classification is purely
// diagnostic, never security-deciding.
func isMiseGlobalPath(path, home, appData string) bool {
	p := filepath.ToSlash(path)
	if home != "" {
		homeSlash := filepath.ToSlash(home)
		if strings.HasPrefix(p, homeSlash+"/.config/mise/") ||
			strings.HasPrefix(p, homeSlash+"/AppData/Roaming/mise/") {
			return true
		}
	}
	if appData != "" {
		if strings.HasPrefix(p, filepath.ToSlash(appData)+"/mise/") {
			return true
		}
	}
	if home == "" && appData == "" {
		if runtime.GOOS == "windows" {
			return strings.Contains(p, "/AppData/Roaming/mise/")
		}
		return strings.Contains(p, "/.config/mise/")
	}
	return false
}

// isMiseSystemPath reports whether a path is under /etc/mise.
func isMiseSystemPath(path string) bool {
	return strings.HasPrefix(filepath.ToSlash(path), "/etc/mise/")
}

// resolveMiseUserDirs returns the user's home directory and the
// Windows APPDATA directory (empty string when either lookup
// fails). Both probes use these to anchor file-kind classification.
func resolveMiseUserDirs() (home, appData string) {
	home, _ = os.UserHomeDir() // empty home is tolerated by the classifier
	appData = os.Getenv("APPDATA")
	return
}

// extractMiseEnvValue normalises a mise env-table entry into a
// (string, redactFlag, ok) triple. Returns ok=false for boolean,
// numeric, or empty-array values that can't carry secrets.
//
// Supported shapes (per mise docs at /environments/):
//
//	FOO = "string"                              bare
//	FOO = ["a", "b"]                            array, joined with \n
//	FOO = { value = "...", redact = true }      table
//	FOO = { file = "/path", redact = true }     dotenv-file reference
//	FOO = { path = "/path", redact = true }     synonym of `file`
//
// `tools = true` / `templated = true` flags are runtime evaluation
// hints; the string value still lives on disk and goes through the
// detector regardless.
func extractMiseEnvValue(raw any) (value string, redact, ok bool) {
	switch v := raw.(type) {
	case string:
		return v, false, true
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return "", false, false
		}
		return strings.Join(parts, "\n"), false, true
	case map[string]any:
		for _, k := range []string{"value", "file", "path"} {
			if s, ok := v[k].(string); ok {
				r, _ := v["redact"].(bool)
				return s, r, true
			}
		}
	}
	return "", false, false
}

// readBoundedMiseFile reads `path` enforcing maxFileSize via
// io.LimitReader. `os.Stat` is a fast-path gate; the LimitReader
// is the authoritative TOCTOU-safe bound. Returns nil on any
// stat/open/read failure (logged at debug).
func readBoundedMiseFile(ctx context.Context, probeName, path string, maxFileSize int64) []byte {
	info, err := os.Stat(path)
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("probe", probeName).Str("file", path).Msg("Cannot stat mise file")
		return nil
	}
	if info.Size() > maxFileSize {
		log.Ctx(ctx).Debug().
			Str("probe", probeName).Str("file", path).
			Int64("size_bytes", info.Size()).Int64("max_size_bytes", maxFileSize).
			Msg("Skipping oversized mise file")
		return nil
	}
	f, err := os.Open(path) //nolint:gosec // path is from the file index, which enforces base-dir + symlink policy
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("probe", probeName).Str("file", path).Msg("Cannot open mise file")
		return nil
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Ctx(ctx).Debug().Err(cerr).Str("probe", probeName).Str("file", path).Msg("Cannot close mise file")
		}
	}()
	content, err := io.ReadAll(io.LimitReader(f, maxFileSize))
	if err != nil {
		log.Ctx(ctx).Debug().Err(err).Str("probe", probeName).Str("file", path).Msg("Cannot read mise file")
		return nil
	}
	return content
}

// miseScanCtx bundles the per-file context shared by every
// env/value-scanning helper call within one file. Pass-by-value
// because all fields are small (one pointer, three strings, one
// flat struct) and the call frequency is low.
type miseScanCtx struct {
	registry  *detector.Registry
	probeName string
	path      string
	class     miseFileClassification
}

// scanEnvTable walks a mise [env] table (or any equivalent
// map[string]any) and runs the detector registry over each value.
// taskName is "" for top-level [env]; non-empty for [tasks.<name>].env
// or for the env block of a file-task header.
//
// The "_" key holds mise directives (`_.file`, `_.source`, `_.path`,
// `_.python.venv`) and is skipped. The line-scan safety net in the
// caller still scans the raw bytes, so a value like
// `_.file = "https://user:pw@host/.env"` is still caught.
func (c miseScanCtx) scanEnvTable(env map[string]any, taskName string) []models.Finding {
	var findings []models.Finding
	for key, raw := range env {
		if key == "_" {
			continue
		}
		value, redact, ok := extractMiseEnvValue(raw)
		if !ok {
			continue
		}
		findings = append(findings, c.scanEnvValue(key, value, taskName, redact)...)
	}
	return findings
}

// scanEnvValue runs the detector registry over one env-var value
// and re-tags every finding with mise-specific metadata. Path,
// Probe, and metadata are reasserted on the finding so the contract
// is robust against detector-side changes.
func (c miseScanCtx) scanEnvValue(key, value, taskName string, redact bool) []models.Finding {
	if c.registry == nil || value == "" {
		return nil
	}
	detCtx := models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    "file:" + c.path,
		ProbeName: c.probeName,
	}).WithEnvVarName(key)

	raw := c.registry.DetectAll(value, detCtx)
	if len(raw) == 0 {
		return nil
	}
	findings := make([]models.Finding, 0, len(raw))
	for _, f := range raw {
		c.annotateEnvFinding(&f, key, taskName, redact)
		findings = append(findings, f)
	}
	return findings
}

// annotateEnvFinding sets the mise-specific metadata, Path, Probe,
// Message, and Description fields on an env-var-derived finding.
// Boolean keys with `false` value are omitted from metadata to keep
// the JSON output compact; consumers should rely on key presence,
// not value.
func (c miseScanCtx) annotateEnvFinding(f *models.Finding, key, taskName string, redact bool) {
	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}
	f.Probe = c.probeName
	f.Path = "file:" + c.path
	f.Metadata["mise_env_var"] = key
	f.Metadata["mise_file_kind"] = c.class.Kind
	f.Metadata["mise_file"] = filepath.Base(c.path)
	if taskName != "" {
		f.Metadata["mise_task_name"] = taskName
		f.Metadata["mise_task_field"] = "env"
	}
	if redact {
		f.Metadata["mise_redact_flag"] = true
	}
	if c.class.IsLocal {
		f.Metadata["mise_file_local"] = true
	}
	if c.class.IsLegacy {
		f.Metadata["mise_file_legacy"] = true
	}
	if c.class.IsFragment {
		f.Metadata["mise_file_fragment"] = true
	}
	if c.class.EnvName != "" {
		f.Metadata["mise_file_env"] = c.class.EnvName
	}
	if redact {
		// `redact = true` only suppresses values in `mise env`
		// output; the secret itself sits in plaintext on disk.
		// Call this out so users don't treat the flag as
		// encryption.
		f.Description = strings.TrimRight(f.Description, " ") +
			" Note: this entry sets `redact = true`, which only " +
			"suppresses the value from `mise env` output. The secret " +
			"itself remains in plaintext on disk."
	}
	if taskName != "" {
		f.Message = fmt.Sprintf("In file:%s: task %q env var %s contains a detected secret", c.path, taskName, key)
	} else {
		f.Message = fmt.Sprintf("In file:%s: env var %s contains a detected secret", c.path, key)
	}
}
