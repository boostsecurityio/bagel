// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPAT = "ghp_1234567890123456789012345678901234567890"

func writeSmallFiles(t testing.TB, n int) []string {
	t.Helper()
	dir := t.TempDir()
	paths := make([]string, n)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("config-%d", i))
		content := fmt.Sprintf("[core]\n\teditor = vim\n\tname = file%d\n", i)
		require.NoError(t, os.WriteFile(paths[i], []byte(content), 0o600))
	}
	return paths
}

func TestScanFileLines_SmallFilesDoNotEachAllocateALineBuffer(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are skewed under -race")
	}
	const n = 200
	paths := writeSmallFiles(t, n)
	registry := detector.NewDefaultRegistry()
	ctx := context.Background()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, p := range paths {
		scanFileLines(ctx, p, "test", registry, 0)
	}
	runtime.ReadMemStats(&after)

	perFile := (after.TotalAlloc - before.TotalAlloc) / n
	assert.Less(t, perFile, uint64(16*1024), "bytes allocated per small file")
}

func TestScanReaderLines_MaxLineSize(t *testing.T) {
	t.Parallel()

	const maxLineSize = 128 * 1024
	pad := func(n int) string { return strings.Repeat("x", n-len(testPAT)-1) + " " + testPAT }

	tests := []struct {
		name      string
		content   string
		wantLines []int
	}{
		{
			name:      "line just under the limit is read whole",
			content:   "first\n" + pad(maxLineSize-1) + "\n" + testPAT + "\n",
			wantLines: []int{2, 3},
		},
		{
			name:      "line over the limit stops the scan",
			content:   testPAT + "\n" + pad(maxLineSize+1) + "\n" + testPAT + "\n",
			wantLines: []int{1},
		},
	}

	registry := detector.NewDefaultRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			findings := scanReaderLines(context.Background(), "test", strings.NewReader(tt.content), "test", registry, maxLineSize)

			lines := make([]int, len(findings))
			for i, f := range findings {
				lines[i] = f.Metadata["line_number"].(int)
			}
			assert.Equal(t, tt.wantLines, lines)
		})
	}
}

func TestScanFileLines_ConcurrentScansKeepTheirOwnLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	registry := detector.NewDefaultRegistry()
	const n = 32
	paths := make([]string, n)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("f%d", i))
		content := strings.Repeat("filler line\n", i) + testPAT + "\n"
		require.NoError(t, os.WriteFile(paths[i], []byte(content), 0o600))
	}

	var wg sync.WaitGroup
	for range 4 {
		for i, p := range paths {
			wg.Go(func() {
				findings := scanFileLines(context.Background(), p, "test", registry, 0)
				if assert.Len(t, findings, 1) {
					assert.Equal(t, "file:"+p, findings[0].Path)
					assert.Equal(t, i+1, findings[0].Metadata["line_number"])
				}
			})
		}
	}
	wg.Wait()
}

func BenchmarkScanFileLines_SmallFiles(b *testing.B) {
	paths := writeSmallFiles(b, 200)
	registry := detector.NewDefaultRegistry()
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		for _, p := range paths {
			scanFileLines(ctx, p, "test", registry, 0)
		}
	}
}
