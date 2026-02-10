---
title: "Why Developers Are Targeted"
slug: developer-targeting
url: /threats/developer-targeting/
---

Developers are targeted because their workstations contain credentials that provide access to critical systems and enable supply chain attacks.

## The Value of Developer Credentials

### Source Code Access

Developer credentials provide access to:

| Repository Type | Attacker Value |
|----------------|----------------|
| Private repos | Intellectual property theft |
| Internal tools | Infrastructure reconnaissance |
| Customer-facing code | Bug hunting for exploitation |

**Impact:** Source code enables attackers to find vulnerabilities, understand architecture, and plan targeted attacks.

### Infrastructure Access

Developers typically have:

- **Cloud console access** - AWS, GCP, Azure credentials
- **Production databases** - Read/write access for debugging
- **Kubernetes clusters** - Deployment and management access
- **CI/CD systems** - Pipeline modification capabilities

**Impact:** Direct path to data theft, cryptocurrency mining, ransomware deployment.

### Supply Chain Position

Developer credentials enable supply chain attacks:

| Credential Type               | Attack Capability |
|-------------------------------|------------------|
| Code Registry Credential      | Publish malicious packages |
| Container Registry Credential | Poison container images |
| CI/CD Pipeline Credentials    | Modify build pipelines |

**Impact:** A single developer compromise can affect thousands of downstream users.

## Credential Lifetime Problem

Unlike traditional users, developer credentials often:

### Long-Lived
```bash
# Token created 2 years ago, never rotated
export GITHUB_TOKEN=ghp_xxxxx
```

Many developers create tokens once and never rotate them.

### Overly Permissive
```bash
# Token with all scopes "just in case"
gh auth login --scopes "repo,admin:org,gist,user,delete_repo"
```

Developers often request maximum permissions for convenience.

### Stored Insecurely
```bash
# Hardcoded in shell config
echo 'export AWS_ACCESS_KEY_ID=AKIAXXXXXXXX' >> ~/.zshrc
```

Credentials in plaintext files are trivial to exfiltrate.

### Widely Distributed
```bash
# Same token in multiple locations
# ~/.bashrc, ~/.zshrc, .env files, IDE configs
```

Credentials spread across multiple files increase exposure.

## The Bottom Line

Developers are targeted because:

1. **High-value credentials** - Access to code, infrastructure, and supply chain
2. **Poor credential hygiene** - Long-lived, overly permissive, insecurely stored
3. **Unique attack surface** - Package managers, git repositories, IDE extensions
4. **Multiplier effect** - One compromise enables many downstream attacks

Understanding this targeting helps prioritize what Bagel detects and why remediation matters.
