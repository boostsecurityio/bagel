---
title: "Environment Probe"
slug: env
url: /probes/env/
---

The **env** probe scans environment variables, shell configuration files, and `.env` files for exposed secrets.

## What It Checks

| Source | Description |
|--------|-------------|
| Environment Variables | All currently set environment variables |
| Shell Config Files | `.bashrc`, `.zshrc`, `.bash_profile`, etc. |
| .env Files | Project and home directory `.env` files |

## Files Scanned

### Shell Configuration
- `~/.bashrc`
- `~/.bash_profile`
- `~/.zshrc`
- `~/.zprofile`
- `~/.profile`

### Environment Files
- `~/.env`
- `.env` in project directories
- `.env.local`, `.env.development`, etc.

## Finding Types

The env probe runs all registered detectors on the scanned content. Common findings include:

| Finding ID | Source | Description |
|-----------|--------|-------------|
| `github-token-*` | Environment variable | GitHub tokens in env vars |
| `ai-service-*` | Shell config | AI API keys in exports |
| `cloud-credential-*` | .env file | Cloud credentials |
| `generic-api-key` | Any | High-entropy secrets |

## Example Findings

### Secret in Environment Variable

```json
{
  "id": "github-token-classic-pat",
  "probe": "env",
  "severity": "critical",
  "title": "GitHub Token Detected (Classic Personal Access Token)",
  "message": "A GitHub Classic Personal Access Token was detected in environment variable GITHUB_TOKEN.",
  "path": "env:GITHUB_TOKEN"
}
```

### Secret in Shell Config

```json
{
  "id": "ai-service-openai-api-key",
  "probe": "env",
  "severity": "critical",
  "title": "AI Service API Key Detected (OpenAI API Key)",
  "message": "An OpenAI API Key was detected in file:/Users/dev/.zshrc.",
  "path": "file:/Users/dev/.zshrc"
}
```

## Best Practices

Use secret managers and only load secrets when needed.

### For Shell History

If secrets appear in your shell config, they may also be in your history. See the [Shell History Probe]({{< relref "/probes/shell-history" >}}) for remediation.
