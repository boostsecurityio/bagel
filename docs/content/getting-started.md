---
title: "Getting Started"
slug: getting-started
url: /getting-started/
---

Get up and running with Bagel.

## Installation

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/boostsecurityio/bagel/releases).

**macOS:**
```bash
# Intel Mac
curl -L https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-darwin-amd64 -o bagel
chmod +x bagel
sudo mv bagel /usr/local/bin/

# Apple Silicon
curl -L https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-darwin-arm64 -o bagel
chmod +x bagel
sudo mv bagel /usr/local/bin/

# Homebrew
brew install bagel
```

**Linux:**
```bash
# x86_64
curl -L https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-linux-amd64 -o bagel
chmod +x bagel
sudo mv bagel /usr/local/bin/

# ARM64
curl -L https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-linux-arm64 -o bagel
chmod +x bagel
sudo mv bagel /usr/local/bin/
```

**Windows:**

Download `bagel-windows-amd64.exe` from the [releases page](https://github.com/boostsecurityio/bagel/releases) and add it to your PATH.

```powershell
# PowerShell
Invoke-WebRequest -Uri "https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-windows-amd64.exe" -OutFile "bagel.exe"
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
bagel --version
```

## Run a Scan

After installing Bagel, run a scan with:

```bash
bagel scan
```

This will scan your workstation and output findings to stdout in JSON format.

### Example Output

```json
{
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
  ],
  "machine_info": {
    "hostname": "dev-laptop",
    "os": "darwin",
    "arch": "arm64"
  }
}
```

### Save Output to File

```bash
bagel scan > bagel-report.json
```

### Pretty Print Output

Use `jq` to format the output:

```bash
bagel scan | jq .
```

### Filter by Severity

Use `jq` to filter findings by severity:

```bash
# Show only critical findings
bagel scan | jq '.findings | map(select(.severity == "critical"))'

# Show high and critical findings
bagel scan | jq '.findings | map(select(.severity == "high" or .severity == "critical"))'
```

## Configuration

Bagel supports various command-line flags:

```bash
bagel scan [flags]
```

### Common Flags

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output format: `json` (default), `text` |
| `--verbose`, `-v` | Enable verbose logging |
| `--config`, `-c` | Path to configuration file |
| `--probe` | Run only specific probes (comma-separated) |
| `--exclude-probe` | Exclude specific probes (comma-separated) |

### Examples

```bash
# Run only git and ssh probes
bagel scan --probe git,ssh

# Exclude shell history scanning
bagel scan --exclude-probe shell_history

# Verbose output for debugging
bagel scan --verbose
```

## Configuration File

Bagel can be configured using a YAML configuration file.

### Default Location

Bagel looks for configuration in these locations (in order):

1. Path specified with `--config` flag
2. `.bagel.yaml` in current directory
3. `~/.config/bagel/config.yaml`
4. `~/.bagel.yaml`

### Configuration Options

```yaml
# .bagel.yaml

# Enable or disable specific probes
probes:
  git:
    enabled: true
  ssh:
    enabled: true
  npm:
    enabled: true
  cloud:
    enabled: true
  env:
    enabled: true
  shell_history:
    enabled: true
  gh:
    enabled: true
  jetbrains:
    enabled: true

# Output configuration
output:
  format: json  # json or text

# Logging level
log_level: info  # debug, info, warn, error
```

### Disabling Probes

To disable a probe, set `enabled: false`:

```yaml
probes:
  shell_history:
    enabled: false  # Don't scan shell history
```

## Environment Variables

Configuration can also be set via environment variables:

| Variable | Description |
|----------|-------------|
| `BAGEL_CONFIG` | Path to configuration file |
| `BAGEL_LOG_LEVEL` | Logging level |

## Platform-Specific Behavior

Some probes behave differently depending on the platform:

| Probe | macOS | Linux | Windows |
|-------|-------|-------|---------|
| ssh (permissions) | Checks Unix permissions | Checks Unix permissions | Skipped (uses ACLs) |
| shell_history | Scans bash/zsh history | Scans bash/zsh history | Scans PowerShell history |

## Next Steps

- Learn what [probes]({{< relref "/probes" >}}) check
- Review the [detectors]({{< relref "/detectors" >}}) for secret patterns
- Understand the [threats]({{< relref "/threats" >}}) targeting developers
