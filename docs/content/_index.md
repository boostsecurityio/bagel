---
title: "bagel"
---

Bagel is a cross-platform CLI that inspects developer workstations and produces a structured report of security findings. It allows developers to understand their attack surface and what could be of interest to a malicious actor.

## Features

- **Security Configuration Scanning** - Detects risky settings in Git, SSH, NPM, cloud CLIs, and IDEs
- **Secret Detection** - Finds exposed credentials in environment variables, shell history, config files (never collects the actual secret values)
- **Cross-Platform** - Works on macOS, Linux, and Windows

## Quick Start

```bash
# Download and install
curl -L https://github.com/boostsecurityio/bagel/releases/latest/download/bagel-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o bagel
chmod +x bagel

# Run a scan
./bagel scan | jq .
```

[Get Started]({{< relref "/getting-started" >}}) | [GitHub](https://github.com/boostsecurityio/bagel)
