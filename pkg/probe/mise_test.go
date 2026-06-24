// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGitHubPAT is a syntactically valid GitHub Classic PAT (ghp_ + 36
// alphanumerics) used purely as a detector fixture. Built at runtime
// from string concatenation so static scanners (gitleaks etc.) don't
// flag it on this test file.
var fakeGitHubPAT = "ghp_" + strings.Repeat("A", 36)

// newMiseTestRegistry returns a detector registry populated with the
// detectors the mise probe is expected to drive. Keep this list aligned
// with cmd/bagel/scan.go's registry so test findings match production.
func newMiseTestRegistry(t *testing.T) *detector.Registry {
	t.Helper()
	r := detector.NewRegistry()
	r.Register(detector.NewGitHubPATDetector())
	r.Register(detector.NewAIServiceDetector())
	r.Register(detector.NewCloudCredentialsDetector())
	return r
}

func TestMiseProbe_Name(t *testing.T) {
	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	assert.Equal(t, "mise", p.Name())
}

func TestMiseProbe_IsEnabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		enabled bool
	}{
		{"enabled", true},
		{"disabled", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewMiseProbe(models.ProbeSettings{Enabled: tt.enabled}, detector.NewRegistry())
			assert.Equal(t, tt.enabled, p.IsEnabled())
		})
	}
}

func TestMiseProbe_ExecuteWithoutFileIndex(t *testing.T) {
	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseProbe_ExecuteEmptyIndex(t *testing.T) {
	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(fileindex.NewFileIndex())
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseProbe_MissingFileFailsSoft(t *testing.T) {
	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", filepath.Join(t.TempDir(), "does-not-exist", "mise.toml"))

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseProbe_InvalidTOMLLineScansAnyway(t *testing.T) {
	// Garbled TOML should not cause the probe to error; the line-scan
	// safety net still runs over the raw bytes and surfaces secrets.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := "this is not = valid [toml\nMISE_GITHUB_TOKEN = " + fakeGitHubPAT + "\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings, "line scan should find token even with broken TOML")

	hasGitHub := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			hasGitHub = true
		}
	}
	assert.True(t, hasGitHub, "expected github-token-classic-pat finding from line scan")
}

func TestExtractMiseEnvValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		raw        any
		wantValue  string
		wantRedact bool
		wantOK     bool
	}{
		{"bare string", "hello", "hello", false, true},
		{"table value", map[string]any{"value": "hello"}, "hello", false, true},
		{
			"table value with redact",
			map[string]any{"value": "secret", "redact": true},
			"secret", true, true,
		},
		{
			"table file reference",
			map[string]any{"file": "/etc/secret"},
			"/etc/secret", false, true,
		},
		{
			"table path reference (synonym for file)",
			map[string]any{"path": "/etc/secret", "redact": true},
			"/etc/secret", true, true,
		},
		{
			"array of strings joined",
			[]any{"a", "b", "c"},
			"a\nb\nc", false, true,
		},
		{
			"array with non-string mixed in",
			[]any{"a", 42, "c"},
			"a\nc", false, true,
		},
		{"empty array", []any{}, "", false, false},
		{"array of non-strings only", []any{1, 2, 3}, "", false, false},
		{"table with non-string value", map[string]any{"value": 42}, "", false, false},
		{"bool", true, "", false, false},
		{"int", 42, "", false, false},
		{"float", 1.5, "", false, false},
		{"nil", nil, "", false, false},
		{"empty map", map[string]any{}, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, redact, ok := extractMiseEnvValue(tt.raw)
			assert.Equal(t, tt.wantOK, ok)
			if ok {
				assert.Equal(t, tt.wantValue, v)
				assert.Equal(t, tt.wantRedact, redact)
			}
		})
	}
}

func TestMiseProbe_DetectsPlaintextSecretInBareEnv(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `"
NORMAL_VAR = "harmless"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	// Probe-internal dedup means we get exactly one finding per token
	// per file: the structured-walk finding with full mise metadata.
	// The line-scan finding for the same fingerprint is suppressed.
	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID != "github-token-classic-pat" {
			continue
		}
		require.Contains(t, f.Metadata, "mise_env_var",
			"only structured walk should produce a github-token finding (line-scan dup should be suppressed)")
		structured = &findings[i]
	}
	require.NotNil(t, structured)
	assert.Equal(t, "MISE_GITHUB_TOKEN", structured.Metadata["mise_env_var"])
	assert.NotContains(t, structured.Metadata, "mise_redact_flag",
		"redact omitted when false")
	assert.Equal(t, "project", structured.Metadata["mise_file_kind"])
	assert.NotContains(t, structured.Metadata, "mise_file_local", "false bool omitted")
	assert.NotContains(t, structured.Metadata, "mise_file_legacy", "false bool omitted")
	assert.NotContains(t, structured.Metadata, "mise_file_env", "no env scope on mise.toml")
	assert.Equal(t, "mise.toml", structured.Metadata["mise_file"])
	assert.Equal(t, "file:"+path, structured.Path)
	assert.Equal(t, "mise", structured.Probe)
	assert.Contains(t, structured.Message, "env var MISE_GITHUB_TOKEN")
	assert.Contains(t, structured.Message, "file:"+path,
		"message should use file: URI prefix, not raw absolute path")
}

func TestMiseProbe_TableFormWithRedactFlag(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".mise.toml")
	content := `[env]
MISE_GITHUB_TOKEN = { value = "` + fakeGitHubPAT + `", redact = true }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured, "structured walk should annotate the redacted entry")
	assert.Equal(t, true, structured.Metadata["mise_redact_flag"])
	assert.Contains(t, structured.Description, "redact = true",
		"description should call out the redact-illusion")
}

func TestMiseProbe_FileReferenceWithRedact(t *testing.T) {
	// `{ file = "...", redact = true }` and `{ path = "...", redact = true }`
	// forms reference dotenv files. The probe extracts the path and runs
	// the detector registry against it - useful when the path itself
	// embeds credentials (e.g. http://user:pw@host/secrets.env).
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
_VALUE_REF = { file = "https://abuser:` + fakeGitHubPAT + `@example.com/.env", redact = true }
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "_VALUE_REF", structured.Metadata["mise_env_var"])
	assert.Equal(t, true, structured.Metadata["mise_redact_flag"])
}

func TestMiseProbe_GlobalConfigKind(t *testing.T) {
	// Simulate the user's resolved home dir + .config/mise/config.toml.
	// classifyMiseFile should tag mise_file_kind="global" because the
	// path starts with `home + /.config/mise/`.
	home := t.TempDir()
	globalDir := filepath.Join(home, ".config", "mise")
	require.NoError(t, os.MkdirAll(globalDir, 0o700))
	path := filepath.Join(globalDir, "config.toml")
	content := `[env]
MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	// Inject the synthetic home so classifyMiseFile anchors correctly
	// without depending on the test machine's real $HOME.
	p.userHome = home
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "global", structured.Metadata["mise_file_kind"])
}

func TestMiseProbe_DotfilesProjectClassifiedAsProject(t *testing.T) {
	// A dotfiles repo checked out at ~/work/myrepo/.config/mise/config.toml
	// must NOT be classified as "global" - the global tag affects how
	// downstream consumers triage findings.
	home := t.TempDir()
	dotfilesPath := filepath.Join(home, "work", "myrepo", ".config", "mise", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(dotfilesPath), 0o700))
	content := `[env]
TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(dotfilesPath, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", dotfilesPath)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.userHome = home
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "project", structured.Metadata["mise_file_kind"],
		"a .config/mise/ inside a project tree must NOT be tagged global")
}

func TestMiseProbe_UnderscoreDirectivesIgnored(t *testing.T) {
	// `_.file`, `_.path`, `_.python.venv` are mise directives, not
	// env-var assignments. They must NOT produce structured findings
	// (line scan can still scan them - but here the values are benign).
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
_.file = ".env"
_.path = "./bin"
NORMAL = "ok"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	for _, f := range findings {
		if v, ok := f.Metadata["mise_env_var"]; ok {
			assert.NotEqual(t, "_", v, "_ directives should not produce env-var findings")
		}
	}
}

func TestMiseProbe_NoEnvTable(t *testing.T) {
	// A mise config without [env] (e.g., one that only configures
	// [tools]) should produce no structured findings.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tools]
go = "latest"
node = "20"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseProbe_CleanConfigProducesNoFindings(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
NODE_ENV = "development"
GOOS = "darwin"

[tools]
node = "20"

[tasks.build]
run = "go build ./..."
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseProbe_OversizedFileSkipped(t *testing.T) {
	// File contains a real-shaped token; size cap=1 means the read is
	// rejected before any scan happens. Neither pass should fire.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(
		models.ProbeSettings{Enabled: true, Flags: map[string]interface{}{"max_file_size": 1}},
		newMiseTestRegistry(t),
	)
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "oversized file should produce zero findings even when it contains a token")
}

func TestMiseProbe_ArrayOfTablesEnv(t *testing.T) {
	// [[env]] is the mise array-of-tables form for grouping multiple
	// `env._.source` directives. The structured walk must descend into
	// each table element, not bail on the type switch.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[[env]]
TOKEN_A = "` + fakeGitHubPAT + `"

[[env]]
NORMAL = "ok"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured, "structured walk should descend into [[env]] tables")
	assert.Equal(t, "TOKEN_A", structured.Metadata["mise_env_var"])
}

func TestMiseProbe_ArrayValueScanned(t *testing.T) {
	// Array values like ["a", "b", token] must be scanned by the
	// structured pass - not just the line scan.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
TOKENS = ["harmless1", "harmless2", "` + fakeGitHubPAT + `"]
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured, "array value should be scanned by structured pass")
	assert.Equal(t, "TOKENS", structured.Metadata["mise_env_var"])
}

func TestMiseProbe_LineScanFindingsNotDuplicatedAgainstStructured(t *testing.T) {
	// Probe-internal dedup must prevent the same token appearing twice
	// when both the structured walk and the line scan see it. The
	// expected outcome: exactly one finding for the token, tagged with
	// mise_env_var.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env]
MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	pat := 0
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			pat++
		}
	}
	assert.Equal(t, 1, pat, "probe should emit exactly one github-token finding per (token, file)")
}

func TestMiseProbe_LineScanStillSurfacesNonStructured(t *testing.T) {
	// A token that appears outside [env] (e.g., inside a [tasks.*].run
	// string) is not visible to the structured walk. The line scan
	// must still surface it - internal dedup only suppresses matches
	// that share a fingerprint with the structured set.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks.deploy]
run = "curl -H 'Authorization: Bearer ` + fakeGitHubPAT + `' https://api.example.com"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	found := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			found = true
			// Token in [tasks] doesn't have mise_env_var (only line scan saw it).
			_, hasMiseEnvVar := f.Metadata["mise_env_var"]
			assert.False(t, hasMiseEnvVar, "tasks.run is invisible to structured walk; line scan owns the finding")
		}
	}
	assert.True(t, found, "line scan should surface a token in [tasks.deploy].run")
}

func TestMiseProbe_RespectsContextCancellation(t *testing.T) {
	// Build a file index with several files. Cancel before Execute
	// runs; the probe must return promptly with the cancellation error.
	tmp := t.TempDir()
	idx := fileindex.NewFileIndex()
	for i := range 5 {
		path := filepath.Join(tmp, "mise.toml")
		if i > 0 {
			path = filepath.Join(tmp, "mise."+string(rune('a'+i))+".toml")
		}
		require.NoError(t, os.WriteFile(path, []byte("[env]\nFOO=\"bar\"\n"), 0o600))
		idx.Add("mise_config", path)
	}

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := p.Execute(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestClassifyMiseFile(t *testing.T) {
	// Drive classifyMiseFile through every documented file shape so
	// the broadening surface has table coverage. Synthetic paths use
	// forward slashes; classifyMiseFile normalises internally.
	t.Parallel()
	const home = "/home/james"
	const appData = "C:/Users/James/AppData/Roaming"

	tests := []struct {
		name         string
		path         string
		wantKind     string
		wantLocal    bool
		wantEnv      string
		wantRtx      bool
		wantFragment bool
	}{
		// ---- Project basenames -----------------------------------------
		{"project mise.toml", home + "/repo/mise.toml", "project", false, "", false, false},
		{"project .mise.toml", home + "/repo/.mise.toml", "project", false, "", false, false},
		{"project mise.local.toml", home + "/repo/mise.local.toml", "project", true, "", false, false},
		{"project .mise.local.toml", home + "/repo/.mise.local.toml", "project", true, "", false, false},
		{"project mise.production.toml", home + "/repo/mise.production.toml", "project", false, "production", false, false},
		{"project .mise.dev.toml", home + "/repo/.mise.dev.toml", "project", false, "dev", false, false},
		{"project mise.staging.local.toml", home + "/repo/mise.staging.local.toml", "project", true, "staging", false, false},
		{"project .mise.staging.local.toml", home + "/repo/.mise.staging.local.toml", "project", true, "staging", false, false},
		// `mise.config.toml` is a user-named non-env file. The denylist
		// must clear EnvName so consumers don't see a meaningless
		// "config" environment tag.
		{"project mise.config.toml (denylisted)", home + "/repo/mise.config.toml", "project", false, "", false, false},
		{"project mise.backup.toml (denylisted)", home + "/repo/mise.backup.toml", "project", false, "", false, false},
		// `mise.local.local.toml` -> strip .local once -> stem = mise.local
		// -> EnvName = "local". This preserves literal intent without
		// silently normalising user typos.
		{"project mise.local.local.toml", home + "/repo/mise.local.local.toml", "project", true, "local", false, false},
		// ---- Idiomatic dir forms (project nested copies) ----------------
		{"project mise/config.toml", home + "/repo/mise/config.toml", "project", false, "", false, false},
		{"project mise/config.local.toml", home + "/repo/mise/config.local.toml", "project", true, "", false, false},
		{"project mise/config.dev.toml", home + "/repo/mise/config.dev.toml", "project", false, "dev", false, false},
		{"project .mise/config.toml", home + "/repo/.mise/config.toml", "project", false, "", false, false},
		{"project .mise/config.prod.local.toml", home + "/repo/.mise/config.prod.local.toml", "project", true, "prod", false, false},
		// `.config/mise.toml` under a project dir -> project (not global,
		// because the global anchor is `<home>/.config/mise/<rest>`).
		{"project .config/mise.toml", home + "/repo/.config/mise.toml", "project", false, "", false, false},
		{"project .config/mise.dev.toml", home + "/repo/.config/mise.dev.toml", "project", false, "dev", false, false},
		// Dotfiles repo with .config/mise/ buried inside a project tree -
		// regression for the substring-match false-positive.
		{"dotfiles project .config/mise/config.toml", home + "/work/myrepo/.config/mise/config.toml", "project", false, "", false, false},
		// ---- Global (home-anchored) -----------------------------------
		{"global config.toml", home + "/.config/mise/config.toml", "global", false, "", false, false},
		{"global config.local.toml", home + "/.config/mise/config.local.toml", "global", true, "", false, false},
		{"global config.dev.toml", home + "/.config/mise/config.dev.toml", "global", false, "dev", false, false},
		{"global config.dev.local.toml", home + "/.config/mise/config.dev.local.toml", "global", true, "dev", false, false},
		{"global mise.toml under .config/mise", home + "/.config/mise/mise.toml", "global", false, "", false, false},
		// conf.d fragments: the filename prefix is a sort key, not an env scope.
		{"global conf.d fragment", home + "/.config/mise/conf.d/01-go.toml", "global", false, "", false, true},
		// ---- Global on Windows (anchored to APPDATA) ------------------
		{"windows global config.toml", appData + "/mise/config.toml", "global", false, "", false, false},
		{"windows global config.local.toml", appData + "/mise/config.local.toml", "global", true, "", false, false},
		// ---- Legacy rtx ------------------------------------------------
		{"legacy .rtx.toml", home + "/repo/.rtx.toml", "project", false, "", true, false},
		{"legacy .rtx.local.toml", home + "/repo/.rtx.local.toml", "project", true, "", true, false},
		{"legacy .rtx.prod.toml", home + "/repo/.rtx.prod.toml", "project", false, "prod", true, false},
		// ---- System ---------------------------------------------------
		{"system config.toml", "/etc/mise/config.toml", "system", false, "", false, false},
		{"system conf.d fragment", "/etc/mise/conf.d/00-base.toml", "system", false, "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifyMiseFile(tt.path, home, appData)
			assert.Equal(t, tt.wantKind, got.Kind, "kind")
			assert.Equal(t, tt.wantLocal, got.IsLocal, "local")
			assert.Equal(t, tt.wantEnv, got.EnvName, "env")
			assert.Equal(t, tt.wantRtx, got.IsLegacy, "legacy")
			assert.Equal(t, tt.wantFragment, got.IsFragment, "fragment")
		})
	}
}

func TestClassifyMiseFile_NoHomeFallback(t *testing.T) {
	// When UserHomeDir failed, classifyMiseFile falls back to a
	// substring heuristic. Document the behaviour so it can't regress
	// silently - and so we know it's a permissive, diagnostic-only
	// fallback (any path containing /.config/mise/ is "global").
	got := classifyMiseFile("/home/anon/.config/mise/config.toml", "", "")
	assert.Equal(t, "global", got.Kind, "substring fallback when home is unknown")
}

func TestMiseProbe_BroadenedFileShapesAnnotateRole(t *testing.T) {
	// Exercise the full per-file annotation path for every
	// significant role. Each fixture is a real file in t.TempDir()
	// with the same content; we only vary the basename so
	// classifyMiseFile sees the role on the path.
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "mise", "conf.d"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "repo"), 0o700))

	content := []byte(`[env]
MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `"
`)

	type expect struct {
		path     string
		kind     string
		local    bool
		envName  string
		legacy   bool
		fragment bool
	}
	cases := []expect{
		{filepath.Join(home, "repo", "mise.toml"), "project", false, "", false, false},
		{filepath.Join(home, "repo", ".mise.toml"), "project", false, "", false, false},
		{filepath.Join(home, "repo", "mise.local.toml"), "project", true, "", false, false},
		{filepath.Join(home, "repo", "mise.production.toml"), "project", false, "production", false, false},
		{filepath.Join(home, "repo", "mise.staging.local.toml"), "project", true, "staging", false, false},
		{filepath.Join(home, "repo", ".rtx.toml"), "project", false, "", true, false},
		{filepath.Join(home, ".config", "mise", "config.toml"), "global", false, "", false, false},
		{filepath.Join(home, ".config", "mise", "config.dev.toml"), "global", false, "dev", false, false},
		{filepath.Join(home, ".config", "mise", "config.local.toml"), "global", true, "", false, false},
		// conf.d fragments: filename prefix is a sort key, NOT an env scope.
		{filepath.Join(home, ".config", "mise", "conf.d", "01-tools.toml"), "global", false, "", false, true},
	}

	idx := fileindex.NewFileIndex()
	for _, c := range cases {
		require.NoError(t, os.WriteFile(c.path, content, 0o600))
		idx.Add("mise_config", c.path)
	}

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.userHome = home
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	byPath := make(map[string]models.Finding)
	for _, f := range findings {
		if _, isStruct := f.Metadata["mise_env_var"]; !isStruct {
			continue
		}
		byPath[strings.TrimPrefix(f.Path, "file:")] = f
	}

	for _, c := range cases {
		t.Run(filepath.Base(c.path), func(t *testing.T) {
			f, ok := byPath[c.path]
			require.True(t, ok, "expected structured finding for %s", c.path)
			assert.Equal(t, c.kind, f.Metadata["mise_file_kind"], "mise_file_kind")
			assertOptionalBool(t, f.Metadata, "mise_file_local", c.local)
			assertOptionalBool(t, f.Metadata, "mise_file_legacy", c.legacy)
			assertOptionalBool(t, f.Metadata, "mise_file_fragment", c.fragment)
			if c.envName != "" {
				assert.Equal(t, c.envName, f.Metadata["mise_file_env"])
			} else {
				assert.NotContains(t, f.Metadata, "mise_file_env", "no env scope expected")
			}
		})
	}
}

// assertOptionalBool checks that an optional bool-valued metadata key
// is either absent (when want=false) or present and true (when
// want=true). The mise probe omits false-valued bool keys to keep
// the JSON output compact.
func assertOptionalBool(t *testing.T, md map[string]interface{}, key string, want bool) {
	t.Helper()
	if want {
		assert.Equal(t, true, md[key], "%s should be present and true", key)
	} else {
		assert.NotContains(t, md, key, "%s should be omitted when false", key)
	}
}

func TestMiseProbe_TaskEnvBlock(t *testing.T) {
	// Secrets in `[tasks.<name>].env` must produce structured
	// findings annotated with mise_task_name + mise_task_field=env.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks.lint]
description = "Lint the code"
env = { MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `" }
run = "cargo clippy"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID != "github-token-classic-pat" {
			continue
		}
		if _, ok := f.Metadata["mise_task_name"]; ok {
			structured = &findings[i]
		}
	}
	require.NotNil(t, structured, "structured walk should annotate task env")
	assert.Equal(t, "lint", structured.Metadata["mise_task_name"])
	assert.Equal(t, "env", structured.Metadata["mise_task_field"])
	assert.Equal(t, "MISE_GITHUB_TOKEN", structured.Metadata["mise_env_var"])
}

func TestMiseProbe_TaskEnvSubtable(t *testing.T) {
	// `[tasks.<name>.env]` sub-table syntax (TOML-equivalent to the
	// inline `env = {...}` form) must produce the same finding.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks.lint]
description = "Lint the code"
run = "cargo clippy"

[tasks.lint.env]
MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_task_name"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "lint", structured.Metadata["mise_task_name"])
	assert.Equal(t, "env", structured.Metadata["mise_task_field"])
}

func TestMiseProbe_TaskRunString(t *testing.T) {
	// A `run` string containing a curl with embedded token must
	// produce a finding with mise_task_field=run.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks.deploy]
run = "curl -H 'Authorization: Bearer ` + fakeGitHubPAT + `' https://api.example.com"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if v, ok := f.Metadata["mise_task_field"]; ok && v == "run" {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured, "task run string should produce a structured finding tagged field=run")
	assert.Equal(t, "deploy", structured.Metadata["mise_task_name"])
	assert.NotContains(t, structured.Metadata, "mise_env_var", "run findings don't have env var names")
}

func TestMiseProbe_TaskRunArray(t *testing.T) {
	// `run` can be an array of strings; each element should be
	// scanned.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks.deploy]
run = [
  "echo starting",
  "curl -H 'Authorization: Bearer ` + fakeGitHubPAT + `' https://api.example.com",
  "echo done",
]
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	hasRunFinding := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			if v, ok := f.Metadata["mise_task_field"]; ok && v == "run" {
				hasRunFinding = true
				assert.Equal(t, "deploy", f.Metadata["mise_task_name"])
			}
		}
	}
	assert.True(t, hasRunFinding, "run array element should produce a structured finding")
}

func TestMiseProbe_TrivialTaskString(t *testing.T) {
	// Trivial task form: `tasks.<name> = "command"`. The string is
	// treated as the task's run value.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[tasks]
deploy = "curl -H 'Authorization: Bearer ` + fakeGitHubPAT + `' https://api.example.com"
build = "cargo build"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		f := findings[i]
		if f.ID == "github-token-classic-pat" {
			if v, ok := f.Metadata["mise_task_name"]; ok && v == "deploy" {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "run", structured.Metadata["mise_task_field"])
}

// FuzzClassifyMiseFile guards classifyMiseFile against panics and
// invariant violations on adversarial input. The function is pure
// and string-driven, so the fuzz is cheap.
func FuzzClassifyMiseFile(f *testing.F) {
	for _, p := range []string{
		"/home/user/mise.toml",
		"/home/user/.config/mise/config.toml",
		"/home/user/.config/mise/conf.d/01-tools.toml",
		"/home/user/repo/mise.production.local.toml",
		"/home/user/repo/.rtx.toml",
		"C:/Users/u/AppData/Roaming/mise/config.toml",
		"/etc/mise/config.toml",
		"",
		"...",
		"/",
		strings.Repeat("/", 100) + "mise.toml",
		`mise.\.toml`,    // regression: backslash in middle segment
		"mise. .toml",    // regression: whitespace in middle segment
		"mise.\x00.toml", // regression: NUL byte in middle segment
	} {
		f.Add(p, "/home/user", "")
	}
	f.Fuzz(func(t *testing.T, path, home, appData string) {
		got := classifyMiseFile(path, home, appData)

		switch got.Kind {
		case miseFileKindGlobal, miseFileKindProject, miseFileKindSystem:
		default:
			t.Fatalf("invalid Kind %q for path %q", got.Kind, path)
		}

		// EnvName must never match the denylist - that's exactly
		// the case classifyMiseFile is designed to filter out.
		if _, deny := envNameDenylist[got.EnvName]; deny {
			t.Fatalf("EnvName %q matched denylist for path %q", got.EnvName, path)
		}

		// conf.d fragments never carry an env scope; the filename
		// prefix is a sort key.
		if got.IsFragment && got.EnvName != "" {
			t.Fatalf("fragment %q must not have EnvName %q", path, got.EnvName)
		}

		// EnvName should never contain a path separator - it's
		// extracted from a single basename segment.
		if strings.ContainsAny(got.EnvName, "/\\") {
			t.Fatalf("EnvName %q contains a path separator (path=%q)", got.EnvName, path)
		}
	})
}

func TestMiseProbe_NestedSubTablesAreNotEnvVars(t *testing.T) {
	// `[env.foo]` is NOT documented as profile scoping in mise (the
	// documented profile mechanism is per-file `mise.<env>.toml`).
	// The probe's structured walk treats `env.foo` as a plain nested
	// table - extractMiseEnvValue rejects it because there's no
	// `value`/`file`/`path` string key. The line-scan safety net
	// still catches secrets via the raw bytes.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mise.toml")
	content := `[env.production]
TOKEN = "` + fakeGitHubPAT + `"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_config", path)

	p := NewMiseProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	hasFinding := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			hasFinding = true
			_, hasMiseMeta := f.Metadata["mise_env_var"]
			assert.False(t, hasMiseMeta, "nested [env.production] table not annotated by structured walk")
		}
	}
	assert.True(t, hasFinding, "line scan should still find the token")
}
