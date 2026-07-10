// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package reporter

import (
	"testing"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestFormatLocation(t *testing.T) {
	t.Run("single location with line number", func(t *testing.T) {
		finding := models.Finding{
			Path: "file:.bashrc",
			Metadata: map[string]interface{}{
				"line_number": 42,
			},
		}
		assert.Equal(t, "file:.bashrc:42", formatLocation(finding))
	})

	t.Run("multiple locations (deduplicated)", func(t *testing.T) {
		finding := models.Finding{
			Path:      "file:.bashrc",
			Locations: []string{"env:TOKEN", "file:.bashrc:42", "file:.zshrc:10"},
		}
		assert.Equal(t, "env:TOKEN, file:.bashrc:42, file:.zshrc:10", formatLocation(finding))
	})

	t.Run("empty path", func(t *testing.T) {
		finding := models.Finding{
			Path: "",
		}
		assert.Equal(t, "-", formatLocation(finding))
	})
}
