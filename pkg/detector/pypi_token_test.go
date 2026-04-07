// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPyPITokenDetector_Detect(t *testing.T) {
	t.Parallel()

	det := NewPyPITokenDetector()

	tests := []struct {
		name      string
		content   string
		source    string
		wantCount int
	}{
		{
			name:      "detect pypi token in pypirc",
			content:   "password = pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw",
			source:    "file:~/.pypirc",
			wantCount: 1,
		},
		{
			name:      "detect pypi token in env var",
			content:   "pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw",
			source:    "env:PYPI_TOKEN",
			wantCount: 1,
		},
		{
			name:      "detect pypi token in shell history",
			content:   "twine upload --password pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw dist/*",
			source:    "file:~/.bash_history",
			wantCount: 1,
		},
		{
			name:      "no token present",
			content:   "repository = https://upload.pypi.org/legacy/",
			source:    "file:~/.pypirc",
			wantCount: 0,
		},
		{
			name:      "pypi- prefix too short",
			content:   "pypi-short",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "empty string",
			content:   "",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name: "multiple tokens",
			content: `password = pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw
password = pypi-BgEIcHlwaS5vcmcCJGI0YjM5ZjYx`,
			source:    "file:~/.pypirc",
			wantCount: 2,
		},
		{
			name:      "duplicate tokens deduplicated",
			content:   "pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw",
			source:    "file:test",
			wantCount: 1,
		},
		{
			name:      "token with hyphens and underscores",
			content:   "pypi-AgEIcHlwaS5vcm_CJG-0YjM5ZjYw",
			source:    "file:~/.pypirc",
			wantCount: 1,
		},
		{
			name:      "token in JSON",
			content:   `{"pypi_token": "pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw"}`,
			source:    "file:config.json",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := det.Detect(tt.content, testCtx(tt.source))
			assert.Len(t, findings, tt.wantCount, "Expected %d findings", tt.wantCount)

			for i, f := range findings {
				assert.Equal(t, "pypi-api-token", f.ID, "Finding %d has wrong ID", i)
				assert.Equal(t, "critical", f.Severity)
				assert.NotEmpty(t, f.Title)
				assert.NotEmpty(t, f.Message)
				assert.Equal(t, "pypi-token", f.Metadata["detector_name"])
				assert.Equal(t, "pypi-api-token", f.Metadata["token_type"])
			}
		})
	}
}

func TestPyPITokenDetector_Redact(t *testing.T) {
	t.Parallel()

	det := NewPyPITokenDetector()

	tests := []struct {
		name      string
		content   string
		want      string
		wantCount int
	}{
		{
			name:      "redact pypi token",
			content:   "password = pypi-AgEIcHlwaS5vcmcCJGI0YjM5ZjYw",
			want:      "password = [REDACTED-pypi-token]",
			wantCount: 1,
		},
		{
			name:      "no token to redact",
			content:   "repository = https://upload.pypi.org/legacy/",
			want:      "repository = https://upload.pypi.org/legacy/",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, counts := det.Redact(tt.content)
			assert.Equal(t, tt.want, result)

			total := 0
			for _, c := range counts {
				total += c
			}
			assert.Equal(t, tt.wantCount, total)
		})
	}
}

func TestPyPITokenDetector_Name(t *testing.T) {
	t.Parallel()

	det := NewPyPITokenDetector()
	require.Equal(t, "pypi-token", det.Name())
}
