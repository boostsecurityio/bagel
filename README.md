# Bagel

> Inventory what matters on developer machines—tools, configs, and **metadata about secrets**—to improve org supply‑chain security without exfiltrating payloads.

---

## What is it?

Bagel is a cross‑platform CLI that inspects developer workstations (macOS, Linux, Windows) and produces a structured report of:

* **Dev tool configurations and risky settings** across 9 probes: Git, SSH, npm, environment variables, shell history, cloud credentials (AWS/GCP/Azure), JetBrains IDEs, GitHub CLI, and AI CLI tools.
* **Secret locations (metadata only)**: presence of tokens, keys, and credentials in config files, env vars, and history—detected by 8 secret detectors—**never the secret values**.

For detailed documentation on each probe and detector, see the [Bagel docs site](https://boostsecurityio.github.io/bagel/).

---

## Privacy & Safety by Design

* **No payloads. Ever.** Bagel records only metadata (path, owner, perms, timestamps, config flags, key type/length/expiry). Secret values are never included in output or written to disk.
* **Local‑first.** Reports are printed to stdout as JSON by default.
* **Minimally intrusive.** Read‑only operations; no process injection; no network scanners.
* **Transparent.** Every probe is documented and can be toggled via configuration.

---

## Why run it?

Modern supply‑chain risk often lands on developer endpoints (malicious packages, misconfig creds, weak key hygiene). Bagel standardizes visibility so security teams can:

* Find high‑signal misconfigs (e.g., `http.sslVerify=false`, `ForwardAgent yes`, plaintext creds files, unencrypted SSH keys).
* Detect leaked secrets in shell history, `.env` files, and config files.
* Enforce baseline posture checks in CI with `--strict`.

---

## Risk checks (examples)

* **Git**: `credential.helper=store`, `http.sslVerify=false`, custom `core.sshCommand` with non‑standard binaries, dangerous protocols, fsck disabled.
* **npm**: tokens in `.npmrc`, `strict-ssl=false`, HTTP (non‑HTTPS) registries.
* **SSH**: keys without passphrase, `ForwardAgent yes`, `StrictHostKeyChecking=no`, permissive file modes.
* **Environment & history**: secrets embedded in env vars, `.env` files, or shell command history.
* **Cloud**: AWS credentials, GCP API keys, Azure storage keys in config files.

---

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/boostsecurityio/bagel/releases).

**macOS:**
```bash
# Intel Mac
curl -sL https://github.com/boostsecurityio/bagel/releases/latest/download/bagel_Darwin_x86_64.tar.gz | tar xz
sudo mv bagel /usr/local/bin/

# Apple Silicon
curl -sL https://github.com/boostsecurityio/bagel/releases/latest/download/bagel_Darwin_arm64.tar.gz | tar xz
sudo mv bagel /usr/local/bin/
```
**Homebrew:**
```bash
brew tap boostsecurityio/tap
brew install bagel
```

**Linux:**
```bash
# x86_64
curl -sL https://github.com/boostsecurityio/bagel/releases/latest/download/bagel_Linux_x86_64.tar.gz | tar xz
sudo mv bagel /usr/local/bin/

# ARM64
curl -sL https://github.com/boostsecurityio/bagel/releases/latest/download/bagel_Linux_arm64.tar.gz | tar xz
sudo mv bagel /usr/local/bin/
```

**Windows:**

Download `bagel_Windows_x86_64.zip` from the [releases page](https://github.com/boostsecurityio/bagel/releases), extract it, and add it to your PATH.

```powershell
Invoke-WebRequest -Uri "https://github.com/boostsecurityio/bagel/releases/latest/download/bagel_Windows_x86_64.zip" -OutFile "bagel.zip"
Expand-Archive -Path "bagel.zip" -DestinationPath "."
```

### Build from Source

Requires Go 1.25 or later.

```bash
git clone https://github.com/boostsecurityio/bagel.git
cd bagel
go build -o bagel ./cmd/bagel
```

### Verify Installation

```bash
bagel version
```

---

## Usage

```bash
bagel scan
```

This scans your workstation and outputs findings to stdout in JSON format.

### Common flags

| Flag | Description |
|------|-------------|
| `--format`, `-f` | Output format: `json` (default), `table` |
| `--output`, `-o` | Write output to a file instead of stdout |
| `--strict` | Exit with code 2 if any findings are detected |
| `--no-cache` | Bypass file index cache and force rebuild |
| `--no-progress` | Disable progress bars |
| `--verbose`, `-v` | Enable verbose (debug) logging |
| `--config` | Path to configuration file |

### Examples

```bash
# Save report to a file
bagel scan -o report.json

# Table output for quick review
bagel scan -f table

# CI gate: fail the build if findings exist
bagel scan --strict

# Debug a specific scan
bagel scan --verbose --no-progress
```

---

## Configuration

Bagel uses a YAML configuration file. It looks for `bagel.yaml` in these locations (in order):

1. Path specified with `--config`
2. Current directory (`./bagel.yaml`)
3. Platform config directory (`~/.config/bagel/bagel.yaml` on Unix, `%APPDATA%\bagel\bagel.yaml` on Windows)

### Example configuration

```yaml
version: 1
probes:
  git:
    enabled: true
  ssh:
    enabled: true
  npm:
    enabled: true
  env:
    enabled: true
  shell_history:
    enabled: true
  cloud:
    enabled: true
  jetbrains:
    enabled: true
  gh:
    enabled: true
  ai_cli:
    enabled: true
privacy:
  redact_paths: []
  exclude_env_prefixes: []
output:
  include_file_hashes: false
  include_file_content: false
```

All probes are enabled by default. To disable a probe, set `enabled: false`.

---

## Output schema (excerpt)

```json
{
  "metadata": {
    "version": "0.1.0",
    "timestamp": "2026-02-10T12:00:00Z",
    "duration": "1.234s"
  },
  "host": {
    "hostname": "dev-laptop",
    "os": "darwin",
    "arch": "arm64",
    "username": "dev",
    "system": {
      "os_version": "15.3",
      "kernel_version": "Darwin 25.2.0",
      "cpu_model": "Apple M1",
      "cpu_cores": 8,
      "ram_total_gb": 16
    }
  },
  "findings": [
    {
      "id": "git-ssl-verify-disabled",
      "probe": "git",
      "severity": "high",
      "title": "Git SSL Verification Disabled",
      "message": "Git is configured to skip SSL certificate verification...",
      "path": "git-config:http.sslverify"
    },
    {
      "id": "ssh-private-key-rsa",
      "probe": "ssh",
      "severity": "critical",
      "title": "Unencrypted SSH Private Key Detected (RSA)",
      "message": "An unencrypted RSA SSH private key was detected...",
      "path": "file:/Users/dev/.ssh/id_rsa"
    }
  ]
}
```

---

## Architecture

* **Probes**: small, hermetic modules that scan specific areas of the system.
* **Detectors**: reusable secret detection patterns used by probes.
* **Collector**: orchestrates probes with timeouts and resource caps.
* **Reporters**: render JSON or table output; emit exit codes for CI.

Each probe declares its scope (user/system), paths touched, env vars read, and risk rules it can emit.

### Current Probes

| Probe | Description | What it checks |
|-------|-------------|----------------|
| `git` | Git configuration security | SSL verification disabled, SSH config issues (StrictHostKeyChecking, UserKnownHostsFile), plaintext credential storage (`credential.helper=store`), dangerous protocols (ext, fd, file), fsck disabled, proxy settings, custom hooks path |
| `ssh` | SSH configuration and key security | `StrictHostKeyChecking=no`, `UserKnownHostsFile=/dev/null`, `ForwardAgent=yes`, private key file permissions, unencrypted private keys |
| `npm` | NPM/Yarn configuration | `.npmrc` and `.yarnrc` files: `strict-ssl=false`, HTTP (non-HTTPS) registries, `always-auth` settings |
| `env` | Environment variables and dotfiles | Environment variables, shell config files (`.bashrc`, `.zshrc`), `.env` files for embedded secrets |
| `shell_history` | Shell history files | `.bash_history`, `.zsh_history` for secrets in command history |
| `cloud` | Cloud provider credentials | AWS (`~/.aws/config`, `~/.aws/credentials`), GCP (`~/.config/gcloud/`), Azure config files |
| `jetbrains` | JetBrains IDE configuration | JetBrains IDE workspace files and configuration for embedded secrets |
| `gh` | GitHub CLI | GitHub CLI authentication tokens and configuration |
| `ai_cli` | AI CLI tools | Credential files and chat logs for Gemini, Codex, Claude, and OpenCode |

### Current Detectors

| Detector | Description | Patterns detected |
|----------|-------------|-------------------|
| `github-token` | GitHub authentication tokens | Classic PAT (`ghp_`), Fine-grained PAT (`github_pat_`), OAuth (`gho_`), App User-to-Server (`ghu_`), App Server-to-Server (`ghs_`), Refresh Token (`ghr_`) |
| `npm-token` | NPM authentication tokens | NPM auth tokens (`npm_*`) |
| `ai-service` | AI service API keys | OpenAI (`sk-`), Anthropic (`sk-ant-api03-`, `sk-ant-admin01-`), Hugging Face (`hf_`, `api_org_`) |
| `http-authentication` | HTTP auth credentials | Bearer tokens, Basic Auth headers, API key headers (`X-API-Key`, etc.), Basic Auth in URLs (`http://user:pass@host`) |
| `ssh-private-key` | SSH private keys | RSA, DSA, EC, OPENSSH, PKCS8 keys; detects encrypted vs unencrypted |
| `cloud-credentials` | Cloud provider credentials | AWS Access Key ID (`AKIA*`, `ASIA*`, etc.), GCP API Key (`AIza*`), Azure Storage Account Key |
| `generic-api-key` | Generic secrets | High-entropy strings matching common secret patterns (uses Shannon entropy analysis) |
| `jwt` | JSON Web Tokens | JWT tokens (`eyJ` prefix with standard JWT structure) |

---

## Platform support

| OS | Support |
|----|---------|
| macOS (Intel & Apple Silicon) | Full support |
| Linux (x86_64 & ARM64) | Full support |
| Windows (x86_64) | Full support with platform-specific file paths and PowerShell history |

All probes work cross-platform with appropriate path handling for each OS.

---

## Integrations

* **CI**: run `bagel scan --strict` in your pipeline to fail builds when findings are detected.

---

## Exit codes

* `0` – success, no findings detected (or `--strict` not set)
* `1` – runtime error
* `2` – findings detected (when using `--strict`)

---

## FAQ

**Does it read my secrets?** No. It only gathers metadata and security‑relevant flags.

**Is it noisy?** Probes are read‑only, batched, and time‑boxed to keep scans under a minute on typical dev machines.

---
