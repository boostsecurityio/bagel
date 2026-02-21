// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

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

func runScrub(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := zerolog.Ctx(ctx)

	// Phase 1: Scan
	scanResult, err := scrubber.Scan(ctx, scrubber.ScanInput{
		GraceMinutes: scrubGraceMinutes,
		File:         scrubFile,
	})
	if err != nil {
		return fmt.Errorf("scrub scan failed: %w", err)
	}

	fmt.Print("\n" + scopeWarning + "\n")
	printScanSummary(scanResult)

	if scanResult.Redactions == 0 {
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
	applyResult, err := scrubber.Apply(ctx, scanResult.Files)
	if err != nil {
		return fmt.Errorf("scrub apply failed: %w", err)
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

func printScanSummary(r scrubber.ScanResult) {
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
