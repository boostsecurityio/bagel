// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package models

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DetectionContext provides probe-specific context to detectors
// This allows probes to pass metadata that gets included in findings
type DetectionContext struct {
	// Source indicates where the content came from (e.g., "env:GITHUB_TOKEN", "file:/path/to/config")
	Source string

	// ProbeName is the name of the probe that invoked the detector
	ProbeName string

	// LineNumber is the 1-based line number where the content was found (0 if not applicable)
	LineNumber int

	// EnvVarName is the environment variable name (empty if not from env)
	EnvVarName string

	// Extra allows probes to pass additional arbitrary metadata
	Extra map[string]any

	// FingerprintSalt is a machine-specific salt (os:arch:hostname:username)
	// used by detectors to produce machine-unique secret fingerprints
	FingerprintSalt string
}

// NewDetectionContext creates a new DetectionContext with required fields
type NewDetectionContextInput struct {
	Source    string
	ProbeName string
}

func NewDetectionContext(input NewDetectionContextInput) *DetectionContext {
	return &DetectionContext{
		Source:    input.Source,
		ProbeName: input.ProbeName,
	}
}

// WithLineNumber sets the line number and returns the context for chaining
func (c *DetectionContext) WithLineNumber(line int) *DetectionContext {
	c.LineNumber = line
	return c
}

// WithEnvVarName sets the environment variable name and returns the context for chaining
func (c *DetectionContext) WithEnvVarName(name string) *DetectionContext {
	c.EnvVarName = name
	return c
}

// WithExtra sets an extra metadata key-value pair and returns the context for chaining
func (c *DetectionContext) WithExtra(key string, value any) *DetectionContext {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}
	c.Extra[key] = value
	return c
}

// FormatSource returns a formatted source string that includes line number if present
func (c *DetectionContext) FormatSource() string {
	if c.LineNumber > 0 {
		return fmt.Sprintf("%s:%d", c.Source, c.LineNumber)
	}
	return c.Source
}

// ScanResult represents the complete scan output
type ScanResult struct {
	Metadata Metadata  `json:"metadata"`
	Host     HostInfo  `json:"host"`
	Findings []Finding `json:"findings"`
}

// Metadata contains scan metadata
type Metadata struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Duration  string    `json:"duration"`
}

// HostInfo contains information about the scanned host
type HostInfo struct {
	Hostname string      `json:"hostname"`
	OS       string      `json:"os"`
	Arch     string      `json:"arch"`
	Username string      `json:"username"`
	System   *SystemInfo `json:"system,omitempty"`
}

// SystemInfo contains detailed system information
type SystemInfo struct {
	OSVersion     string    `json:"os_version,omitempty"`
	KernelVersion string    `json:"kernel_version,omitempty"`
	CPUModel      string    `json:"cpu_model,omitempty"`
	CPUCores      int       `json:"cpu_cores,omitempty"`
	RAMTotalGB    float64   `json:"ram_total_gb,omitempty"`
	BootTime      time.Time `json:"boot_time,omitempty"`
	Timezone      string    `json:"timezone,omitempty"`
}

// FingerprintSalt returns a machine-specific salt derived from host identity fields.
// Used by detectors to produce machine-unique secret fingerprints.
func (h *HostInfo) FingerprintSalt() string {
	return strings.Join([]string{h.OS, h.Arch, h.Hostname, h.Username}, ":")
}

// Fingerprint computes a SHA-256 hash of a value for deduplication purposes.
// This allows identifying the same secret across different locations without storing the actual value.
func Fingerprint(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// SaltedFingerprint computes an HMAC-SHA256 of value using salt as the key.
// Used by detectors to produce machine-unique fingerprints for detected secrets.
func SaltedFingerprint(value, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// FingerprintFromFields computes a fingerprint from multiple identifying fields.
// Use this for config-based findings where the fingerprint is derived from stable attributes
// like finding ID, path, and other discriminating fields.
func FingerprintFromFields(fields ...string) string {
	// Use an unambiguous encoding (JSON) to avoid collisions when fields contain ":" or other separators.
	data, err := json.Marshal(fields)
	if err != nil {
		// Fallback to the previous behavior if JSON encoding unexpectedly fails.
		return Fingerprint(strings.Join(fields, ":"))
	}
	return Fingerprint(string(data))
}

// Finding represents a single security finding
type Finding struct {
	ID          string                 `json:"id"`
	Fingerprint string                 `json:"fingerprint"`
	Probe       string                 `json:"probe"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Path        string                 `json:"path,omitempty"`
	Locations   []string               `json:"locations,omitempty"` // Additional locations when deduplicated
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
