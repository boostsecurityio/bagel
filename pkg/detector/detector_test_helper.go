// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import "github.com/boostsecurityio/bagel/pkg/models"

// testCtx creates a DetectionContext for testing purposes
func testCtx(source string) *models.DetectionContext {
	return models.NewDetectionContext(models.NewDetectionContextInput{
		Source:    source,
		ProbeName: "test",
	})
}
