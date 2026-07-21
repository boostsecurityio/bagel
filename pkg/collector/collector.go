// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/boostsecurityio/bagel/pkg/cache"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/boostsecurityio/bagel/pkg/probe"
	"github.com/boostsecurityio/bagel/pkg/progress"
	"github.com/boostsecurityio/bagel/pkg/sysinfo"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

// Collector orchestrates probe execution
type Collector struct {
	probes     []probe.Probe
	config     *models.Config
	noCache    bool
	noProgress bool
	cacheStore *cache.Store         // Reused across load/save operations
	fileIndex  *fileindex.FileIndex // Prebuilt index; when non-nil, Collect skips building/caching its own
}

// NewInput holds the parameters for creating a new Collector
type NewInput struct {
	Probes     []probe.Probe
	Config     *models.Config
	NoCache    bool
	NoProgress bool
	// FileIndex, when non-nil, is used as-is; Collect skips building and
	// caching its own index. Lets a caller own the crawl (e.g. share one
	// index across bagel's probes and its own).
	FileIndex *fileindex.FileIndex
}

// New creates a new Collector
func New(input NewInput) *Collector {
	var store *cache.Store
	if !input.NoCache {
		// Best effort initialization - nil store is handled gracefully
		store, _ = cache.NewStore()
	}
	return &Collector{
		probes:     input.Probes,
		config:     input.Config,
		noCache:    input.NoCache,
		noProgress: input.NoProgress,
		cacheStore: store,
		fileIndex:  input.FileIndex,
	}
}

// shouldShowProgress determines if progress bars should be displayed
func (c *Collector) shouldShowProgress() bool {
	if c.noProgress {
		return false
	}
	return isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())
}

// Collect runs all enabled probes and collects findings
func (c *Collector) Collect(ctx context.Context) (*models.ScanResult, error) {
	startTime := time.Now()

	// Get host info
	hostInfo, err := c.getHostInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get host info: %w", err)
	}

	// Use a caller-supplied index as-is; otherwise build (and cache) our own.
	fileIdx := c.fileIndex
	if fileIdx == nil {
		var err error
		fileIdx, err = c.buildFileIndex(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to build file index: %w", err)
		}
	}

	// Compute fingerprint salt from host identity and propagate to probes
	salt := hostInfo.FingerprintSalt()
	for _, p := range c.probes {
		if saltAware, ok := p.(probe.FingerprintSaltAware); ok {
			saltAware.SetFingerprintSalt(salt)
		}
	}

	// Execute probes concurrently
	results := c.executeProbes(ctx, fileIdx)

	// Combine findings
	var allFindings []models.Finding
	logger := zerolog.Ctx(ctx)
	for _, result := range results {
		if result.Error != nil {
			logger.Warn().
				Err(result.Error).
				Str("probe", result.ProbeName).
				Msg("Probe execution failed")
			continue
		}
		allFindings = append(allFindings, result.Findings...)
	}

	duration := time.Since(startTime)

	return &models.ScanResult{
		Metadata: models.Metadata{
			Version:   "0.1.0",
			Timestamp: startTime,
			Duration:  duration.String(),
		},
		Host:     *hostInfo,
		Findings: allFindings,
	}, nil
}

// buildFileIndex constructs the file index based on configuration, delegating
// to the exported BuildFileIndex and rendering progress with a terminal bar
// when appropriate.
func (c *Collector) buildFileIndex(ctx context.Context) (*fileindex.FileIndex, error) {
	var store *cache.Store
	if !c.noCache {
		store = c.cacheStore
	}

	var reporter progress.Reporter = progress.NoOp{}
	if c.shouldShowProgress() {
		reporter = newBarReporter("Indexing files")
	}

	return BuildFileIndex(ctx, c.config, store, reporter)
}

// barReporter renders progress as a terminal spinner via progressbar. The bar
// is created lazily in Start so nothing is shown when a crawl never begins
// (e.g. a cache hit). It implements progress.Reporter.
type barReporter struct {
	description string
	bar         *progressbar.ProgressBar
}

func newBarReporter(description string) *barReporter {
	return &barReporter{description: description}
}

func (b *barReporter) Start() {
	b.bar = progressbar.NewOptions(-1,
		progressbar.OptionSetDescription(b.description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionShowCount(),
	)
}

func (b *barReporter) Update(processed int64) {
	if b.bar != nil {
		_ = b.bar.Set64(processed)
	}
}

func (b *barReporter) Done() {
	if b.bar != nil {
		_ = b.bar.Finish()
	}
}

// executeProbes runs all enabled probes concurrently with timeouts using errgroup.
// It respects context cancellation and ensures goroutine lifecycle is properly managed.
// Results are collected via a buffered channel for idiomatic Go communication.
func (c *Collector) executeProbes(ctx context.Context, fileIdx *fileindex.FileIndex) []probe.Result {
	enabledCount := 0
	for _, p := range c.probes {
		if p.IsEnabled() {
			enabledCount++
		}
	}

	if enabledCount == 0 {
		return []probe.Result{}
	}

	// Set up progress bar for probe execution
	var bar *progressbar.ProgressBar
	if c.shouldShowProgress() {
		bar = progressbar.NewOptions(enabledCount,
			progressbar.OptionSetDescription("Running probes"),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
		)
	}

	probeTimeout := resolveProbeTimeout(ctx, c.config.Resources.ProbeTimeout)

	g, gCtx := errgroup.WithContext(ctx)
	if c.config.Resources.MaxConcurrentProbes > 0 {
		g.SetLimit(c.config.Resources.MaxConcurrentProbes)
	}

	resultChan := make(chan probe.Result, enabledCount)

	for _, p := range c.probes {
		if !p.IsEnabled() {
			continue
		}

		prb := p

		// Provide file index to probes that support it
		if fileIdx != nil {
			if fileIndexAware, ok := prb.(probe.FileIndexAware); ok {
				fileIndexAware.SetFileIndex(fileIdx)
			}
		}

		g.Go(func() error {
			probeCtx, cancel := context.WithTimeout(gCtx, probeTimeout)
			defer cancel()

			findings, err := prb.Execute(probeCtx)

			resultChan <- probe.Result{
				ProbeName: prb.Name(),
				Findings:  findings,
				Error:     err,
			}

			return nil
		})
	}

	go func() {
		_ = g.Wait()
		close(resultChan)
	}()

	results := make([]probe.Result, 0, enabledCount)
	for result := range resultChan {
		results = append(results, result)
		if bar != nil {
			_ = bar.Add(1)
		}
	}

	if bar != nil {
		_ = bar.Finish()
	}

	return results
}

// defaultProbeTimeout is used when Resources.ProbeTimeout is empty or invalid.
const defaultProbeTimeout = 30 * time.Second

// resolveProbeTimeout parses the configured duration. Empty, zero, or invalid
// values fall back to defaultProbeTimeout; invalid values are logged so the
// misconfiguration is visible but non-fatal.
func resolveProbeTimeout(ctx context.Context, raw string) time.Duration {
	if raw == "" {
		return defaultProbeTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		log.Ctx(ctx).Warn().
			Err(err).
			Str("value", raw).
			Dur("fallback", defaultProbeTimeout).
			Msg("Invalid resources.probe_timeout; using default")
		return defaultProbeTimeout
	}
	if d <= 0 {
		return defaultProbeTimeout
	}
	return d
}

// getHostInfo retrieves information about the current host
func (c *Collector) getHostInfo(ctx context.Context) (*models.HostInfo, error) {
	logger := zerolog.Ctx(ctx)

	hostname, err := sysinfo.GetStableHostname()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}

	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows
	}

	hostInfo := &models.HostInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Username: username,
	}

	// Collect extended info if enabled
	if c.config.HostInfo.Extended {
		extendedInfo, err := sysinfo.Collect(ctx)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to collect extended host info")
		} else if extendedInfo != nil && extendedInfo.System != nil {
			hostInfo.System = &models.SystemInfo{
				OSVersion:     extendedInfo.System.OSVersion,
				KernelVersion: extendedInfo.System.KernelVersion,
				CPUModel:      extendedInfo.System.CPUModel,
				CPUCores:      extendedInfo.System.CPUCores,
				RAMTotalGB:    extendedInfo.System.RAMTotalGB,
				BootTime:      extendedInfo.System.BootTime,
				Timezone:      extendedInfo.System.Timezone,
			}
		}
	}

	return hostInfo, nil
}
