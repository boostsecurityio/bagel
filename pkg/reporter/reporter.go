// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/olekukonko/tablewriter"
)

// Format represents the output format
type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
)

// Reporter handles output formatting and reporting
type Reporter struct {
	format Format
	output io.Writer
}

// New creates a new Reporter
func New(format Format, output io.Writer) *Reporter {
	if output == nil {
		output = os.Stdout
	}
	return &Reporter{
		format: format,
		output: output,
	}
}

// Report outputs the scan results in the configured format
func (r *Reporter) Report(result *models.ScanResult) error {
	// Deduplicate findings based on fingerprint
	dedupedResult := deduplicateFindings(result)

	switch r.format {
	case FormatJSON:
		return r.reportJSON(dedupedResult)
	case FormatTable:
		return r.reportTable(dedupedResult)
	default:
		return fmt.Errorf("unsupported output format: %s", r.format)
	}
}

// reportJSON outputs results as JSON
func (r *Reporter) reportJSON(result *models.ScanResult) error {
	encoder := json.NewEncoder(r.output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

// reportTable outputs results in a human-readable table format using tablewriter
func (r *Reporter) reportTable(result *models.ScanResult) error {

	// Host information table
	hostTable := tablewriter.NewWriter(r.output)
	hostTable.Header("Property", "Value")
	if err := hostTable.Append("Hostname", result.Host.Hostname); err != nil {
		return fmt.Errorf("failed to append hostname: %w", err)
	}
	if err := hostTable.Append("OS", result.Host.OS); err != nil {
		return fmt.Errorf("failed to append OS: %w", err)
	}
	if err := hostTable.Append("Architecture", result.Host.Arch); err != nil {
		return fmt.Errorf("failed to append architecture: %w", err)
	}
	if err := hostTable.Append("User", result.Host.Username); err != nil {
		return fmt.Errorf("failed to append user: %w", err)
	}
	if err := hostTable.Append("Scan Time", result.Metadata.Timestamp.Format("2006-01-02 15:04:05")); err != nil {
		return fmt.Errorf("failed to append scan time: %w", err)
	}
	if err := hostTable.Append("Duration", result.Metadata.Duration); err != nil {
		return fmt.Errorf("failed to append duration: %w", err)
	}
	if err := hostTable.Render(); err != nil {
		return fmt.Errorf("failed to render host table: %w", err)
	}

	fmt.Fprintf(r.output, "\n")

	// Extended system information
	if result.Host.System != nil {
		if err := r.renderSystemInfo(result.Host.System); err != nil {
			return fmt.Errorf("render system info: %w", err)
		}
		fmt.Fprintf(r.output, "\n")
	}

	// Findings section
	if len(result.Findings) == 0 {
		fmt.Fprintf(r.output, "✓ No findings detected.\n\n")
		return nil
	}

	fmt.Fprintf(r.output, "Findings: %d\n\n", len(result.Findings))

	// Findings table
	findingsTable := tablewriter.NewWriter(r.output)
	findingsTable.Header("#", "Severity", "Probe", "Title", "Message", "Location")

	for i, finding := range result.Findings {
		location := formatLocation(finding)
		if err := findingsTable.Append(
			strconv.Itoa(i+1),
			finding.Severity,
			finding.Probe,
			finding.Title,
			finding.Message,
			location,
		); err != nil {
			return fmt.Errorf("failed to append finding: %w", err)
		}
	}
	if err := findingsTable.Render(); err != nil {
		return fmt.Errorf("failed to render findings table: %w", err)
	}

	fmt.Fprintf(r.output, "\n")
	return nil
}

// formatLocation creates a human-readable location string from finding metadata
func formatLocation(finding models.Finding) string {
	// If we have deduplicated locations, show them all
	if len(finding.Locations) > 0 {
		return strings.Join(finding.Locations, ", ")
	}

	if finding.Path == "" {
		return "-"
	}

	location := finding.Path

	// Append line number if present
	if lineNum, ok := finding.Metadata["line_number"]; ok {
		location = fmt.Sprintf("%s:%v", location, lineNum)
	}

	// Append env var name if present and not already in the path
	if envVar, ok := finding.Metadata["env_var"]; ok {
		envVarStr := fmt.Sprintf("%v", envVar)
		if envVarStr != "" && !containsEnvVar(location, envVarStr) {
			location = fmt.Sprintf("%s (env: %s)", location, envVarStr)
		}
	}

	return location
}

// containsEnvVar checks if the location already references the env var
func containsEnvVar(location, envVar string) bool {
	return len(location) >= len("env:"+envVar) && location[4:4+len(envVar)] == envVar
}

// deduplicateFindings groups findings by fingerprint and consolidates locations
func deduplicateFindings(result *models.ScanResult) *models.ScanResult {
	if result == nil || len(result.Findings) == 0 {
		return result
	}

	// Map fingerprint -> first finding with that fingerprint
	seen := make(map[string]int) // fingerprint -> index in dedupedFindings
	var dedupedFindings []models.Finding

	for _, finding := range result.Findings {
		fingerprint, hasFingerprint := finding.Metadata["fingerprint"].(string)

		// If no fingerprint, keep the finding as-is (no dedup possible)
		if !hasFingerprint || fingerprint == "" {
			dedupedFindings = append(dedupedFindings, finding)
			continue
		}

		location := formatLocationFromFinding(finding)

		if idx, exists := seen[fingerprint]; exists {
			// Add this location to the existing finding
			if dedupedFindings[idx].Locations == nil {
				// First duplicate - add the original path as first location
				dedupedFindings[idx].Locations = []string{
					formatLocationFromFinding(dedupedFindings[idx]),
				}
			}
			dedupedFindings[idx].Locations = append(dedupedFindings[idx].Locations, location)
		} else {
			// First occurrence of this fingerprint
			seen[fingerprint] = len(dedupedFindings)
			dedupedFindings = append(dedupedFindings, finding)
		}
	}

	return &models.ScanResult{
		Metadata: result.Metadata,
		Host:     result.Host,
		Findings: dedupedFindings,
	}
}

// formatLocationFromFinding creates a location string from a finding's path and metadata
func formatLocationFromFinding(finding models.Finding) string {
	if finding.Path == "" {
		return "-"
	}

	location := finding.Path

	// Append line number if present
	if lineNum, ok := finding.Metadata["line_number"]; ok {
		location = fmt.Sprintf("%s:%v", location, lineNum)
	}

	return location
}

// renderSystemInfo displays extended system information in table format
func (r *Reporter) renderSystemInfo(sys *models.SystemInfo) error {
	fmt.Fprintf(r.output, "System Information:\n")

	sysTable := tablewriter.NewWriter(r.output)
	sysTable.Header("Property", "Value")

	if sys.OSVersion != "" {
		if err := sysTable.Append("OS Version", sys.OSVersion); err != nil {
			return fmt.Errorf("append os version: %w", err)
		}
	}
	if sys.KernelVersion != "" {
		if err := sysTable.Append("Kernel", sys.KernelVersion); err != nil {
			return fmt.Errorf("append kernel: %w", err)
		}
	}
	if sys.CPUModel != "" {
		if err := sysTable.Append("CPU", sys.CPUModel); err != nil {
			return fmt.Errorf("append cpu: %w", err)
		}
	}
	if sys.CPUCores > 0 {
		if err := sysTable.Append("CPU Cores", strconv.Itoa(sys.CPUCores)); err != nil {
			return fmt.Errorf("append cpu cores: %w", err)
		}
	}
	if sys.RAMTotalGB > 0 {
		if err := sysTable.Append("RAM", fmt.Sprintf("%.1f GB", sys.RAMTotalGB)); err != nil {
			return fmt.Errorf("append ram: %w", err)
		}
	}
	if !sys.BootTime.IsZero() {
		if err := sysTable.Append("Boot Time", sys.BootTime.Format("2006-01-02 15:04:05")); err != nil {
			return fmt.Errorf("append boot time: %w", err)
		}
	}
	if sys.Timezone != "" {
		if err := sysTable.Append("Timezone", sys.Timezone); err != nil {
			return fmt.Errorf("append timezone: %w", err)
		}
	}

	if err := sysTable.Render(); err != nil {
		return fmt.Errorf("render system table: %w", err)
	}
	return nil
}
