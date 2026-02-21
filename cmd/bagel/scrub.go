// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"sort"

	"github.com/boostsecurityio/bagel/pkg/scrubber"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	scrubConfirm      bool
	scrubGraceMinutes int
	scrubFile         string
)

// scrubCmd represents the scrub command
var scrubCmd = &cobra.Command{
	Use:   "scrub",
	Short: "Remove credentials from AI CLI session logs",
	Long: `Scrub replaces credential patterns in AI CLI session logs with
[REDACTED-<type>] markers. Preserves all conversation context --
only secrets become useless.

By default runs in dry-run mode. Use --confirm to apply changes.

Targets:
  ~/.claude/projects/**/*.jsonl    Claude Code session logs
  ~/.claude/projects/**/*.txt      Claude Code tool results
  ~/.codex/sessions/**/*.jsonl     Codex CLI session logs
  ~/.gemini/tmp/*/chats/*.json     Gemini CLI chat logs
  ~/.local/share/opencode/**/*.json  OpenCode session logs`,
	RunE: runScrub,
}

func init() {
	rootCmd.AddCommand(scrubCmd)

	scrubCmd.Flags().BoolVar(
		&scrubConfirm, "confirm", false,
		"apply changes (default is dry-run)")
	scrubCmd.Flags().IntVar(
		&scrubGraceMinutes, "grace-minutes", 60,
		"skip files modified within this many minutes")
	scrubCmd.Flags().StringVar(
		&scrubFile, "file", "",
		"scrub a single file instead of all eligible files")
}

func runScrub(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	log := zerolog.Ctx(ctx)

	result, err := scrubber.Run(ctx, scrubber.RunInput{
		Confirm:      scrubConfirm,
		GraceMinutes: scrubGraceMinutes,
		File:         scrubFile,
	})
	if err != nil {
		return fmt.Errorf("scrub failed: %w", err)
	}

	mode := "[DRY RUN] "
	if scrubConfirm {
		mode = ""
	}

	log.Info().
		Str("mode", mode).
		Int("files_scanned", result.FilesScanned).
		Int("files_modified", result.FilesModified).
		Int("redactions", result.Redactions).
		Msg("Scrub complete")

	// Print summary to stdout for user visibility
	fmt.Printf("\n%sScrub complete:\n", mode)
	fmt.Printf("  Files scanned:  %d\n", result.FilesScanned)
	fmt.Printf("  Files modified: %d\n", result.FilesModified)
	fmt.Printf("  Redactions:     %d\n", result.Redactions)

	if len(result.CountsByType) > 0 {
		fmt.Println("  By type:")
		sorted := sortedKeys(result.CountsByType)
		for _, k := range sorted {
			fmt.Printf("    %s: %d\n", k, result.CountsByType[k])
		}
	}

	return nil
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
