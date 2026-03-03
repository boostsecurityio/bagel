// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/boostsecurityio/bagel/pkg/collector"
	"github.com/boostsecurityio/bagel/pkg/config"
	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/boostsecurityio/bagel/pkg/probe"
	"github.com/boostsecurityio/bagel/pkg/scrubber"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	scrubYes          bool
	scrubDryRun       bool
	scrubGraceMinutes int
	scrubFile         string
)

// scrubCmd represents the scrub command
var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Remove credentials from AI CLI session logs and shell history",
	Long: `Scrub replaces credential patterns in AI CLI session logs and shell
history files with [REDACTED-<type>] markers. Preserves all context --
only secrets become useless.

By default shows what would be changed and asks for confirmation.
Use --yes to skip the prompt, or --dry-run to only report.

Targets:
  ~/.claude/projects/**/*.jsonl      Claude Code session logs
  ~/.codex/sessions/**/*.jsonl       Codex CLI session logs
  ~/.gemini/tmp/*/chats/*.json       Gemini CLI chat logs
  ~/.local/share/opencode/**/*.json  OpenCode session logs
  ~/.bash_history                    Bash shell history
  ~/.zsh_history                     Zsh shell history
  ~/.sh_history                      Generic shell history
  ~/.local/share/fish/fish_history   Fish shell history`,
	RunE: runScrub,
}

func init() {
	rootCmd.AddCommand(scrubCmd)

	scrubCmd.Flags().BoolVarP(
		&scrubYes, "yes", "y", false,
		"skip confirmation prompt and apply changes")
	scrubCmd.Flags().BoolVar(
		&scrubDryRun, "dry-run", false,
		"scan and report only, do not modify files")
	scrubCmd.Flags().IntVar(
		&scrubGraceMinutes, "grace-minutes", 60,
		"skip files modified within this many minutes")
	scrubCmd.Flags().StringVar(
		&scrubFile, "file", "",
		"scrub a single file instead of all eligible files")
}

const scopeWarning = `NOTE: bagel scrub redacts credentials found in session logs and shell
history files. It does NOT rotate or revoke exposed credentials.
Credentials that appeared in these files may already be compromised.

For findings requiring manual action (key rotation, re-encryption),
run 'bagel scan' and follow the remediation guidance.
`

// newScrubRegistry builds a detector registry configured for redaction.
// Registration order matters: specific patterns before general ones.
func newScrubRegistry() *detector.Registry {
	registry := detector.NewRegistry()
	registry.Register(detector.NewSSHPrivateKeyDetector())
	registry.Register(detector.NewHTTPAuthDetector())
	registry.Register(detector.NewAIServiceDetector())
	registry.Register(detector.NewCloudCredentialsDetector())
	registry.Register(detector.NewSplunkTokenDetector())
	registry.Register(detector.NewGitHubPATDetector())
	registry.Register(detector.NewNPMTokenDetector())
	registry.Register(detector.NewJWTDetector())
	registry.Register(detector.NewGenericAPIKeyDetector())
	return registry
}

func runScrub(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := zerolog.Ctx(ctx)

	registry := newScrubRegistry()

	// Resolve target files
	files, err := resolveScrubFiles(cmd, registry)
	if err != nil {
		return err
	}

	// Phase 1: Preview
	previewResult, err := scrubber.Preview(ctx, scrubber.PreviewInput{
		Files:    files,
		Registry: registry,
	})
	if err != nil {
		return fmt.Errorf("scrub preview: %w", err)
	}

	fmt.Print("\n" + scopeWarning + "\n")
	printPreviewSummary(previewResult)

	if previewResult.Redactions == 0 {
		fmt.Println("Nothing to scrub.")
		return nil
	}

	// Phase 2: Decide whether to apply
	if scrubDryRun {
		fmt.Println("[DRY RUN] No files were modified.")
		return nil
	}

	if !scrubYes {
		if !isInteractive() {
			fmt.Println("Non-interactive terminal detected. Use --yes to apply, or --dry-run to scan only.")
			return nil
		}
		if !promptConfirm() {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Phase 3: Apply
	applyResult, err := scrubber.Apply(ctx, scrubber.ApplyInput{
		Files:    previewResult.Files,
		Registry: registry,
	})
	if err != nil {
		return fmt.Errorf("scrub apply: %w", err)
	}

	log.Info().
		Int("files_modified", applyResult.FilesModified).
		Int("redactions", applyResult.Redactions).
		Msg("Scrub complete")

	fmt.Printf("\nScrub applied:\n")
	fmt.Printf("  Files modified: %d\n", applyResult.FilesModified)
	fmt.Printf("  Redactions:     %d\n", applyResult.Redactions)
	printCountsByType(applyResult.CountsByType)

	return nil
}

// resolveScrubFiles determines which files to scrub. When --file is set, it
// targets that single file. Otherwise it runs the scan pipeline (FileIndex +
// probes) and extracts file paths from findings.
func resolveScrubFiles(cmd *cobra.Command, registry *detector.Registry) ([]string, error) {
	if scrubFile != "" {
		if _, err := os.Stat(scrubFile); err != nil {
			return nil, fmt.Errorf("file not found: %s", scrubFile)
		}
		return []string{scrubFile}, nil
	}

	ctx := cmd.Context()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	probes := []probe.Probe{
		probe.NewAICliProbe(cfg.Probes.AICli, registry),
		probe.NewShellHistoryProbe(cfg.Probes.ShellHistory, registry),
	}

	col := collector.New(collector.NewInput{
		Probes:     probes,
		Config:     cfg,
		NoCache:    true,
		NoProgress: true,
	})

	result, err := col.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	files := uniqueFilePaths(result.Findings)
	files = filterByGracePeriod(files, scrubGraceMinutes)

	return files, nil
}

// uniqueFilePaths extracts deduplicated file paths from findings.
// Finding.Path uses the format "file:/path/to/file" (sometimes with
// ":lineNum" appended by FormatSource); we strip the "file:" prefix.
func uniqueFilePaths(findings []models.Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	paths := make([]string, 0, len(findings))

	for _, f := range findings {
		p := f.Path
		p, _ = strings.CutPrefix(p, "file:")

		// Strip trailing ":lineNum" if present (e.g. "file:/path:42")
		if idx := strings.LastIndex(p, ":"); idx > 0 {
			candidate := p[:idx]
			if _, err := os.Stat(candidate); err == nil {
				p = candidate
			}
		}

		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}

	return paths
}

// filterByGracePeriod removes files modified within the last graceMins
// minutes. Files with unreadable metadata are silently skipped.
func filterByGracePeriod(files []string, graceMins int) []string {
	if graceMins <= 0 {
		return files
	}

	cutoff := time.Now().Add(-time.Duration(graceMins) * time.Minute)
	filtered := make([]string, 0, len(files))

	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			filtered = append(filtered, path)
		}
	}

	return filtered
}

func printPreviewSummary(r scrubber.PreviewResult) {
	fmt.Printf("Scan results:\n")
	fmt.Printf("  Files scanned:       %d\n", r.FilesScanned)
	fmt.Printf("  Files with secrets:  %d\n", len(r.Files))
	fmt.Printf("  Total redactions:    %d\n", r.Redactions)
	printCountsByType(r.CountsByType)
	if len(r.Files) > 0 {
		fmt.Printf("  Files:\n")
		for _, f := range r.Files {
			fmt.Printf("    %s\n", f)
		}
	}
	fmt.Println()
}

func printCountsByType(counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	fmt.Println("  By type:")
	for _, k := range sortedKeys(counts) {
		fmt.Printf("    %s: %d\n", k, counts[k])
	}
}

func isInteractive() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) ||
		isatty.IsCygwinTerminal(os.Stdin.Fd())
}

func promptConfirm() bool {
	fmt.Print("Proceed with scrubbing? [y/N] ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	return answer == "y" || answer == "yes"
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
