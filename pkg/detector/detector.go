// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"regexp"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/models"
)

// Detector defines the interface for secret/credential detectors
type Detector interface {
	// Name returns the detector name (e.g., "github-pat", "aws-access-key")
	Name() string

	// Detect scans the input text and returns findings if secrets are detected
	// The context parameter provides probe-specific metadata about where the content came from
	Detect(content string, ctx *models.DetectionContext) []models.Finding
}

// Redactor is optionally implemented by detectors that support
// content redaction (find-and-replace of secrets).
type Redactor interface {
	Redact(content string) (string, map[string]int)
}

// RedactPattern holds a compiled regex for content redaction.
type RedactPattern struct {
	Regex       *regexp.Regexp
	Replacement string
	Label       string
	Prefixes    []string
}

// Registry manages all registered detectors
type Registry struct {
	detectors       []Detector
	fingerprintSalt string
}

// NewRegistry creates a new detector registry
func NewRegistry() *Registry {
	return &Registry{
		detectors: []Detector{},
	}
}

// SetFingerprintSalt sets the machine-specific salt used for secret fingerprinting.
func (r *Registry) SetFingerprintSalt(salt string) {
	r.fingerprintSalt = salt
}

// Register adds a detector to the registry
func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

// DetectAll runs all registered detectors against the content
// The context parameter provides probe-specific metadata that gets included in findings
func (r *Registry) DetectAll(content string, ctx *models.DetectionContext) []models.Finding {
	// Propagate the registry's fingerprint salt to the detection context
	ctx.FingerprintSalt = r.fingerprintSalt

	findings := make([]models.Finding, 0, len(r.detectors))

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

// RedactAll runs all registered detectors that implement Redactor.
// Detectors are applied in registration order.
func (r *Registry) RedactAll(content string) (string, map[string]int) {
	counts := make(map[string]int)
	for _, det := range r.detectors {
		red, ok := det.(Redactor)
		if !ok {
			continue
		}
		var detCounts map[string]int
		content, detCounts = red.Redact(content)
		for k, v := range detCounts {
			counts[k] += v
		}
	}
	return content, counts
}

// ApplyRedactPatterns applies redaction patterns to content, returning
// the redacted text and a map of label to match count.
func ApplyRedactPatterns(
	content string,
	patterns []RedactPattern,
) (string, map[string]int) {
	counts := make(map[string]int)
	for _, p := range patterns {
		if !containsAny(content, p.Prefixes) {
			continue
		}
		matches := p.Regex.FindAllString(content, -1)
		if len(matches) > 0 {
			counts[p.Label] += len(matches)
			content = p.Regex.ReplaceAllString(content, p.Replacement)
		}
	}
	return content, counts
}

func containsAny(content string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}
