---
title: "Threats"
slug: threats
url: /threats/
---

Developers are increasingly targeted by info stealer malware, because their workstations contain high-value credentials to critical resources often with elevated permissions given the nature of their work.

## What You'll Learn

- [Why Developers Are Targeted]({{< relref "/threats/developer-targeting" >}}) - The value of developer credentials
- [Defense Strategies]({{< relref "/threats/defense-strategies" >}}) - How to protect yourself and how Bagel helps

## The Growing Threat

Malware targeting developers has been increasing in number and sophistication. Threat actors have recognized that targeting the developers is an efficient way to compromise the software supply chain and gain access to valuable resources.

## Why This Matters for Developers

A compromised developer workstation typically contains:

| Credential Type | Potential Impact |
|----------------|------------------|
| GitHub/GitLab tokens | Source code access, supply chain attacks |
| Cloud credentials (AWS/GCP/Azure) | Infrastructure compromise, data theft |
| SSH keys | Access to production servers |
| CI/CD tokens | Pipeline manipulation |
| Package manager tokens (npm/PyPI) | Supply chain attacks |
| AI service keys | Financial abuse, data exposure |

## How Bagel Helps

Bagel identifies exposed credentials before attackers do:

1. **Detects risky configurations** that make exfiltration easier
2. **Finds exposed secrets** in common locations info stealers target
3. **Reports metadata only** - you learn about exposure without creating new risk
4. **Provides remediation guidance** for each finding
