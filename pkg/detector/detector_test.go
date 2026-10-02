// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
)

var cleanLines = []string{
	"",
	"export PATH=/usr/local/bin:$PATH",
	`  "name": "my-package",`,
	"password = token key secret",
	"sk_ ghp_ AKIA eyJ xoxb- npm_ pypi-",
}

func TestRegistry_DetectAllCleanLineAllocatesNothing(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are skewed under -race")
	}
	r := NewDefaultRegistry()
	ctx := &models.DetectionContext{Source: "file:/tmp/x", ProbeName: "test"}

	for _, line := range cleanLines {
		t.Run(line, func(t *testing.T) {
			allocs := testing.AllocsPerRun(100, func() {
				r.DetectAll(line, ctx)
			})
			assert.Zero(t, allocs)
			assert.Empty(t, r.DetectAll(line, ctx))
		})
	}
}

func TestRegistry_DetectAllKeepsRegistrationOrder(t *testing.T) {
	t.Parallel()

	r := NewDefaultRegistry()
	ctx := &models.DetectionContext{Source: "file:/tmp/x", ProbeName: "test", LineNumber: 3}
	line := "sk_live_" + "abcdefghijklmnopqrstuvwx1234 ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"

	findings := r.DetectAll(line, ctx)

	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
		assert.Equal(t, "test", f.Probe)
		assert.Equal(t, 3, f.Metadata["line_number"])
	}
	assert.Equal(t, []string{"github-token-classic-pat", "stripe-secret-key"}, ids)
}

func BenchmarkRegistry_DetectAllCleanLines(b *testing.B) {
	r := NewDefaultRegistry()
	ctx := &models.DetectionContext{Source: "file:/tmp/x", ProbeName: "test"}
	b.ReportAllocs()
	for b.Loop() {
		for _, line := range cleanLines {
			r.DetectAll(line, ctx)
		}
	}
}
