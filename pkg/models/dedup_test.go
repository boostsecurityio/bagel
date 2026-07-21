// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeduplicateFindings(t *testing.T) {
	t.Run("no findings", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{},
		}
		deduped := DeduplicateFindings(result)
		assert.Empty(t, deduped.Findings)
	})

	t.Run("nil result", func(t *testing.T) {
		deduped := DeduplicateFindings(nil)
		assert.Nil(t, deduped)
	})

	t.Run("no duplicates", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					ID:          "finding-1",
					Fingerprint: "abc123",
					Path:        "file1.txt",
				},
				{
					ID:          "finding-2",
					Fingerprint: "def456",
					Path:        "file2.txt",
				},
			},
		}
		deduped := DeduplicateFindings(result)
		require.Len(t, deduped.Findings, 2)
		assert.Nil(t, deduped.Findings[0].Locations)
		assert.Nil(t, deduped.Findings[1].Locations)
	})

	t.Run("duplicate fingerprints consolidated", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					ID:          "finding-1",
					Fingerprint: "same-fingerprint",
					Path:        "env:GITHUB_TOKEN",
				},
				{
					ID:          "finding-1",
					Fingerprint: "same-fingerprint",
					Path:        "file:.bashrc",
					Metadata: map[string]interface{}{
						"line_number": 42,
					},
				},
				{
					ID:          "finding-1",
					Fingerprint: "same-fingerprint",
					Path:        "file:.zshrc",
					Metadata: map[string]interface{}{
						"line_number": 10,
					},
				},
			},
		}
		deduped := DeduplicateFindings(result)
		require.Len(t, deduped.Findings, 1)
		require.Len(t, deduped.Findings[0].Locations, 3)
		assert.Equal(t, "env:GITHUB_TOKEN", deduped.Findings[0].Locations[0])
		assert.Equal(t, "file:.bashrc:42", deduped.Findings[0].Locations[1])
		assert.Equal(t, "file:.zshrc:10", deduped.Findings[0].Locations[2])
	})

	t.Run("findings without fingerprint not deduplicated", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					ID:       "finding-1",
					Path:     "file1.txt",
					Metadata: map[string]interface{}{},
				},
				{
					ID:       "finding-2",
					Path:     "file2.txt",
					Metadata: nil,
				},
			},
		}
		deduped := DeduplicateFindings(result)
		require.Len(t, deduped.Findings, 2)
	})

	t.Run("mixed findings with and without fingerprints", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					ID:          "secret-1",
					Fingerprint: "fp1",
					Path:        "file1.txt",
				},
				{
					ID:   "config-issue",
					Path: "config.yaml",
				},
				{
					ID:          "secret-1",
					Fingerprint: "fp1",
					Path:        "file2.txt",
				},
			},
		}
		deduped := DeduplicateFindings(result)
		require.Len(t, deduped.Findings, 2)
		// First finding should have 2 locations (deduplicated).
		require.Len(t, deduped.Findings[0].Locations, 2)
		// Second finding should have no locations (not deduplicated).
		assert.Nil(t, deduped.Findings[1].Locations)
	})
}
