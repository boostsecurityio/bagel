// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// Fingerprint computes a SHA-256 hash of a secret for deduplication purposes.
// This allows identifying the same secret across different locations without storing the actual value.
func Fingerprint(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// Detector defines the interface for secret/credential detectors
type Detector interface {
	// Name returns the detector name (e.g., "github-pat", "aws-access-key")
	Name() string

	// Detect scans the input text and returns findings if secrets are detected
	// The context parameter provides probe-specific metadata about where the content came from
	Detect(content string, ctx *models.DetectionContext) []models.Finding
}

// Registry manages all registered detectors
type Registry struct {
	detectors []Detector
}

// NewRegistry creates a new detector registry
func NewRegistry() *Registry {
	return &Registry{
		detectors: []Detector{},
	}
}

// Register adds a detector to the registry
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// DetectAll runs all registered detectors against the content
// The context parameter provides probe-specific metadata that gets included in findings
func (r *Registry) DetectAll(content string, ctx *models.DetectionContext) []models.Finding {
	var findings []models.Finding

	for _, det := range r.detectors {
		detectorFindings := det.Detect(content, ctx)

		// Enrich each finding with context metadata
		for i := range detectorFindings {
			detectorFindings[i].Probe = ctx.ProbeName

			// Add context metadata to finding
			if detectorFindings[i].Metadata == nil {
				detectorFindings[i].Metadata = make(map[string]any)
			}

			if ctx.LineNumber > 0 {
				detectorFindings[i].Metadata["line_number"] = ctx.LineNumber
			}
			if ctx.EnvVarName != "" {
				detectorFindings[i].Metadata["env_var"] = ctx.EnvVarName
			}

			// Copy extra metadata
			for k, v := range ctx.Extra {
				detectorFindings[i].Metadata[k] = v
			}
		}

		findings = append(findings, detectorFindings...)
	}

	return findings
}

// GetDetectors returns all registered detectors
func (r *Registry) GetDetectors() []Detector {
	return r.detectors
}
