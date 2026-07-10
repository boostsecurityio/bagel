// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/models"
)

// DefaultProbes returns every built-in probe wired to cfg and registry, in the
// same set and order the bagel CLI runs. Probes are returned regardless of their
// enabled flag; callers filter on Probe.IsEnabled (the collector already skips
// disabled probes at execution time).
func DefaultProbes(cfg *models.Config, registry *detector.Registry) []Probe {
	return []Probe{
		NewGitProbe(cfg.Probes.Git, registry),
		NewEnvProbe(cfg.Probes.Env, registry),
		NewNPMProbe(cfg.Probes.NPM, registry),
		NewSSHProbe(cfg.Probes.SSH, registry),
		NewShellHistoryProbe(cfg.Probes.ShellHistory, registry),
		NewCloudProbe(cfg.Probes.Cloud, registry),
		NewJetBrainsProbe(cfg.Probes.JetBrains, registry),
		NewGHProbe(cfg.Probes.GH, registry),
		NewAICredentialsProbe(cfg.Probes.AICredentials, registry),
		NewAIChatsProbe(cfg.Probes.AIChats, registry),
		NewWireGuardProbe(cfg.Probes.WireGuard, registry),
		NewPyPIProbe(cfg.Probes.PyPI, registry),
		NewKubeProbe(cfg.Probes.Kube, registry),
		NewDockerProbe(cfg.Probes.Docker, registry),
		NewIaCProbe(cfg.Probes.IaC, registry),
		NewMCPProbe(cfg.Probes.AIMCP, registry),
		NewContextProbe(cfg.Probes.AIContext, registry),
	}
}
