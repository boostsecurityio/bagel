---
title: "Probes"
slug: probes
url: /probes/
---

Bagel uses **probes** to examine different aspects of your developer environment. Each probe focuses on a specific tool or configuration area and generates findings when it detects security issues.

## Available Probes

| Probe | Description | Platforms |
|-------|-------------|-----------|
| [git]({{< relref "/probes/git" >}}) | Git configuration security | All |
| [ssh]({{< relref "/probes/ssh" >}}) | SSH configuration and key security | All |
| [npm]({{< relref "/probes/npm" >}}) | NPM/Yarn package manager configuration | All |
| [cloud]({{< relref "/probes/cloud" >}}) | Cloud provider credential files | All |
| [env]({{< relref "/probes/env" >}}) | Environment variables and shell configs | All |
| [shell_history]({{< relref "/probes/shell-history" >}}) | Shell command history | All |
| [gh]({{< relref "/probes/github-cli" >}}) | GitHub CLI authentication | All |
| [jetbrains]({{< relref "/probes/jetbrains" >}}) | JetBrains IDE configurations | All |
| [ai_cli]({{< relref "/probes/ai-cli" >}}) | AI CLI tool credentials and chat logs | All |

## How Probes Work

Each probe:

1. **Locates relevant files** using a pre-built file index
2. **Analyzes configuration** for insecure settings
3. **Runs detectors** to find exposed secrets
4. **Generates findings** with actionable remediation guidance

The pre-built file index has a cache functionality to speed up subsequent scans by avoiding redundant file system operations. It has a TTL of 30 minutes and detects modification to folders. You can disable the cache with the `--no-cache` flag.

## Probe Categories

### Configuration Probes

These probes check tool configurations for insecure settings:

- **git** - SSL verification, credential storage, hooks
- **ssh** - Host key checking, agent forwarding, key permissions
- **npm** - SSL verification, registry security

### Secret Detection Probes

These probes scan content for exposed credentials:

- **env** - Environment variables and .env files
- **shell_history** - Command history files
- **cloud** - Cloud provider credential files
- **jetbrains** - IDE run configurations
- **ai_cli** - AI CLI credential files and chat logs

### Authentication Probes

These probes check for active authentication sessions:

- **gh** - GitHub CLI authenticated sessions

## Customizing Probes

You can enable or disable probes in the configuration file:

```yaml
probes:
  shell_history:
    enabled: false  # Skip shell history scanning
  git:
    enabled: true
```

Or via command line:

```bash
# Run only specific probes
bagel scan --probe git,ssh

# Exclude specific probes
bagel scan --exclude-probe shell_history
```
