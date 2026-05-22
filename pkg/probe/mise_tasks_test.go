// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiseTasksProbe_Name(t *testing.T) {
	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, detector.NewRegistry())
	assert.Equal(t, "mise_tasks", p.Name())
}

func TestMiseTasksProbe_IsEnabled(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		enabled bool
	}{{"enabled", true}, {"disabled", false}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := NewMiseTasksProbe(models.ProbeSettings{Enabled: tt.enabled}, detector.NewRegistry())
			assert.Equal(t, tt.enabled, p.IsEnabled())
		})
	}
}

func TestMiseTasksProbe_ExecuteWithoutFileIndex(t *testing.T) {
	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseTasksProbe_ExecuteEmptyIndex(t *testing.T) {
	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(fileindex.NewFileIndex())
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseTasksProbe_LineScansBody(t *testing.T) {
	// The most common shape: a bash script in mise-tasks/ with a
	// token pasted into a curl invocation. The line scan must catch
	// it, with the finding tagged mise_task_file=true and
	// mise_task_name derived from the path.
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "deploy")
	body := `#!/usr/bin/env bash
set -euo pipefail
curl -H "Authorization: Bearer ` + fakeGitHubPAT + `" https://api.example.com
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var f *models.Finding
	for i := range findings {
		if findings[i].ID == "github-token-classic-pat" {
			f = &findings[i]
			break
		}
	}
	require.NotNil(t, f, "line scan should find the token in the script body")
	assert.Equal(t, true, f.Metadata["mise_task_file"])
	assert.Equal(t, "deploy", f.Metadata["mise_task_name"])
	assert.Equal(t, "mise_tasks", f.Probe)
	assert.Equal(t, "file:"+taskPath, f.Path)
}

func TestMiseTasksProbe_ParsesHashMiseEnvHeader(t *testing.T) {
	// `#MISE env={ TOKEN = "..." }` should be decoded as inline TOML
	// and surfaced as a structured finding with mise_task_field=env.
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "build")
	body := `#!/usr/bin/env bash
#MISE description="Build the CLI"
#MISE env={ MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `" }
cargo build
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		if findings[i].ID == "github-token-classic-pat" {
			if _, ok := findings[i].Metadata["mise_env_var"]; ok {
				structured = &findings[i]
				break
			}
		}
	}
	require.NotNil(t, structured, "header parse should produce a structured finding")
	assert.Equal(t, "MISE_GITHUB_TOKEN", structured.Metadata["mise_env_var"])
	assert.Equal(t, "env", structured.Metadata["mise_task_field"])
	assert.Equal(t, "build", structured.Metadata["mise_task_name"])
	assert.Equal(t, true, structured.Metadata["mise_task_file"])
}

func TestMiseTasksProbe_HandlesSlashSlashMiseHeader(t *testing.T) {
	// JS/TS/Deno tasks use `//MISE` comments instead of `#MISE`.
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "greet")
	body := `#!/usr/bin/env node
//MISE description="Greet the world"
//MISE env={ TOKEN = "` + fakeGitHubPAT + `" }
console.log("hello");
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	hasStructured := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				hasStructured = true
				assert.Equal(t, "TOKEN", f.Metadata["mise_env_var"])
			}
		}
	}
	assert.True(t, hasStructured, "//MISE header should be parsed")
}

func TestMiseTasksProbe_HandlesMiseBracketWorkaround(t *testing.T) {
	// `# [MISE] env={...}` is the documented workaround for
	// formatters that rewrite `#MISE` to `# MISE`.
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "test")
	body := `#!/usr/bin/env bash
# [MISE] description="Test the thing"
# [MISE] env={ MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `" }
cargo test
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	hasStructured := false
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			if _, ok := f.Metadata["mise_env_var"]; ok {
				hasStructured = true
			}
		}
	}
	assert.True(t, hasStructured, "# [MISE] header should be parsed")
}

func TestMiseTasksProbe_MergesMultipleHeaders(t *testing.T) {
	// Multiple `#MISE env=` headers must merge into one env map
	// before scanning. Each header's inline TOML is decoded
	// independently; last writer wins on key conflicts.
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "multi")
	body := `#!/usr/bin/env bash
#MISE env={ TOKEN_A = "` + fakeGitHubPAT + `" }
#MISE env={ TOKEN_B = "harmless" }
echo "go"
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var structured *models.Finding
	for i := range findings {
		if findings[i].ID == "github-token-classic-pat" {
			if _, ok := findings[i].Metadata["mise_env_var"]; ok {
				structured = &findings[i]
			}
		}
	}
	require.NotNil(t, structured)
	assert.Equal(t, "TOKEN_A", structured.Metadata["mise_env_var"])
}

func TestMiseTasksProbe_CleanScriptNoFindings(t *testing.T) {
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "myrepo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "build")
	body := `#!/usr/bin/env bash
#MISE description="Build the CLI"
#MISE env={ NODE_ENV = "production" }
set -euo pipefail
cargo build
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestMiseTasksProbe_RespectsContextCancellation(t *testing.T) {
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	idx := fileindex.NewFileIndex()
	for _, name := range []string{"a", "b", "c"} {
		p := filepath.Join(taskDir, name)
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\necho ok\n"), 0o700))
		idx.Add("mise_task_file", p)
	}

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Execute(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDeriveMiseTaskName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		want string
	}{
		{"mise-tasks single", "/home/x/repo/mise-tasks/build", "build"},
		{"mise-tasks nested", "/home/x/repo/mise-tasks/test/units", "test:units"},
		{"mise-tasks _default collapses", "/home/x/repo/mise-tasks/test/_default", "test"},
		{"mise-tasks 3 levels", "/home/x/repo/mise-tasks/a/b/c", "a:b:c"},
		{".mise-tasks nested", "/home/x/repo/.mise-tasks/lint/go", "lint:go"},
		{"mise/tasks/", "/home/x/repo/mise/tasks/build", "build"},
		{".mise/tasks/", "/home/x/repo/.mise/tasks/build", "build"},
		{".config/mise/tasks/ (global)", "/home/x/.config/mise/tasks/global-build", "global-build"},
		{".config/mise/tasks/ nested", "/home/x/.config/mise/tasks/db/migrate", "db:migrate"},
		// Fallback: path lacks any task-root marker. Returns basename.
		{"unknown path falls back to basename", "/tmp/loose-script.sh", "loose-script.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, deriveMiseTaskName(tt.path))
		})
	}
}

func TestParseMiseTaskHeaderEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    map[string]any
	}{
		{
			"no header",
			"#!/usr/bin/env bash\necho hi\n",
			nil,
		},
		{
			"single hash MISE",
			"#!/usr/bin/env bash\n#MISE env={ FOO = \"bar\" }\n",
			map[string]any{"FOO": "bar"},
		},
		{
			"slash-slash MISE",
			"#!/usr/bin/env node\n//MISE env={ FOO = \"bar\" }\n",
			map[string]any{"FOO": "bar"},
		},
		{
			"bracket workaround",
			"#!/usr/bin/env bash\n# [MISE] env={ FOO = \"bar\" }\n",
			map[string]any{"FOO": "bar"},
		},
		{
			"multiple headers merge",
			"#MISE env={ A = \"1\" }\n#MISE env={ B = \"2\" }\n",
			map[string]any{"A": "1", "B": "2"},
		},
		{
			"multiple headers last writer wins on conflict",
			"#MISE env={ KEY = \"first\" }\n#MISE env={ KEY = \"second\" }\n",
			map[string]any{"KEY": "second"},
		},
		{
			"unparseable header is dropped, others still parse",
			"#MISE env=not-a-toml-value\n#MISE env={ OK = \"v\" }\n",
			map[string]any{"OK": "v"},
		},
		{
			"#MISE without env directive is ignored",
			"#MISE description=\"hi\"\n",
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseMiseTaskHeaderEnv(context.Background(), []byte(tt.content), "<test>")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMiseTasksProbe_GlobalTaskClassifiedAsGlobal(t *testing.T) {
	// A file task under ~/.config/mise/tasks/ should be tagged
	// mise_file_kind=global because the path is under the resolved
	// home dir's .config/mise/.
	home := t.TempDir()
	taskDir := filepath.Join(home, ".config", "mise", "tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "global-task")
	body := `#!/usr/bin/env bash
curl -H "Authorization: Bearer ` + fakeGitHubPAT + `" https://api.example.com
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.userHome = home // inject synthetic home for hermetic test
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	var f *models.Finding
	for i := range findings {
		if findings[i].ID == "github-token-classic-pat" {
			f = &findings[i]
			break
		}
	}
	require.NotNil(t, f)
	assert.Equal(t, "global", f.Metadata["mise_file_kind"])
	assert.Equal(t, "global-task", f.Metadata["mise_task_name"])
}

func TestMiseTasksProbe_LineScanFindingsNotDuplicatedAgainstHeader(t *testing.T) {
	// When the same token appears in both a `#MISE env=` header
	// AND the body of a script, probe-internal dedup must collapse
	// to a single finding (the header-derived one with full
	// metadata).
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "repo", "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "dupe")
	body := `#!/usr/bin/env bash
#MISE env={ MISE_GITHUB_TOKEN = "` + fakeGitHubPAT + `" }
echo "$MISE_GITHUB_TOKEN"
curl -H "Authorization: Bearer ` + fakeGitHubPAT + `" https://example.com
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(models.ProbeSettings{Enabled: true}, newMiseTestRegistry(t))
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)

	pat := 0
	for _, f := range findings {
		if f.ID == "github-token-classic-pat" {
			pat++
		}
	}
	assert.Equal(t, 1, pat, "structured header finding should suppress line-scan duplicates")
}

func TestMiseTasksProbe_OversizedFileSkipped(t *testing.T) {
	tmp := t.TempDir()
	taskDir := filepath.Join(tmp, "mise-tasks")
	require.NoError(t, os.MkdirAll(taskDir, 0o700))
	taskPath := filepath.Join(taskDir, "big")
	body := `#!/usr/bin/env bash
curl -H "Authorization: Bearer ` + fakeGitHubPAT + `" https://api.example.com
`
	require.NoError(t, os.WriteFile(taskPath, []byte(body), 0o700))

	idx := fileindex.NewFileIndex()
	idx.Add("mise_task_file", taskPath)

	p := NewMiseTasksProbe(
		models.ProbeSettings{Enabled: true, Flags: map[string]interface{}{"max_file_size": 1}},
		newMiseTestRegistry(t),
	)
	p.SetFileIndex(idx)
	findings, err := p.Execute(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "oversized task file should produce zero findings")
}
