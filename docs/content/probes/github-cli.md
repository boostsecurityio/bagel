---
title: "GitHub CLI Probe"
slug: github-cli
url: /probes/github-cli/
---

The **gh** probe checks if the GitHub CLI (`gh`) has an active authenticated session on your machine.

## What It Checks

| Check | Finding ID | Severity | Description |
|-------|-----------|----------|-------------|
| Active Session | `gh-auth-token-present` | Medium | gh CLI is authenticated |

## How It Works

The probe runs `gh auth token` to check if there's an active authentication session. It only checks the exit code - **the actual token is never stored or logged**.

If `gh auth token` returns exit code 0, an authentication session exists.

## Finding

### gh-auth-token-present

**Severity:** Medium

The GitHub CLI has an active authenticated session on this machine.

**Why This Matters:**

If your machine is compromised, an attacker could use the `gh` CLI to:
- Access your GitHub repositories (including private ones)
- Read organization data you have access to
- Create/modify issues, PRs, and releases
- Access GitHub Actions secrets
- Modify repository settings
- Steal you GitHub token for further abuse

**Example Finding:**
```json
{
  "id": "gh-auth-token-present",
  "probe": "gh",
  "severity": "medium",
  "title": "GitHub CLI Authentication Detected",
  "message": "The GitHub CLI (gh) has an active authenticated session on this machine...",
  "path": "/usr/local/bin/gh"
}
```

## Remediation

### Option 1: Limit Token Permissions

When authenticating, select minimal scopes:

```bash
gh auth login --scopes "repo,read:org"
```

## Checking Your Authentication Status

```bash
# See what accounts are authenticated
gh auth status

# See what scopes your token has
gh auth status 2>&1 | grep -i scope
```

## Related

- [GitHub Token Detector]({{< relref "/detectors/github-token" >}}) - Detects GitHub tokens in files and environment variables
