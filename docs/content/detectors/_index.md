---
title: "Detectors"
slug: detectors
url: /detectors/
---

Bagel uses **detectors** to identify exposed secrets in the content scanned by probes. Each detector specializes in a specific type of credential and uses regular expressions and heuristics to minimize false positives.

## Available Detectors

| Detector | Description | Severity |
|----------|-------------|----------|
| [GitHub Token]({{< relref "/detectors/github-token" >}}) | GitHub PATs and app tokens | Critical |
| [SSH Private Key]({{< relref "/detectors/ssh-private-key" >}}) | SSH private keys (encrypted/unencrypted) | Critical/Low |
| [Cloud Credentials]({{< relref "/detectors/cloud-credentials" >}}) | AWS, GCP, Azure credentials | Critical |
| [AI Service]({{< relref "/detectors/ai-service" >}}) | OpenAI, Anthropic, HuggingFace keys | Critical |
| [Generic API Key]({{< relref "/detectors/generic-api-key" >}}) | High-entropy secrets | High |
| [HTTP Auth]({{< relref "/detectors/http-auth" >}}) | Bearer tokens, Basic auth, API keys | Critical |
| [JWT]({{< relref "/detectors/jwt" >}}) | JWT and JWE tokens | Critical |
| [NPM Token]({{< relref "/detectors/npm-token" >}}) | NPM authentication tokens | Critical |

## How Detectors Work

1. **Pattern Matching** - Each detector uses regex patterns specific to its credential type
2. **Validation** - Additional checks (entropy, format) reduce false positives
3. **Fingerprinting** - Detected secrets are SHA-256 hashed for deduplication without storing actual values
4. **Context Enrichment** - Findings include probe context (file, line number, environment variable name)

## Severity Levels

| Level | Description |
|-------|-------------|
| **Critical** | Active credentials that provide direct access to systems |
| **High** | Likely credentials or high-entropy secrets |
| **Medium** | Configuration issues that could lead to exposure |
| **Low** | Informational findings or encrypted credentials |

## Detection vs. Exposure

Bagel reports **metadata about secrets**, never the actual values:

```json
{
  "id": "github-token-classic-pat",
  "fingerprint": "sha256:a1b2c3...",
  "severity": "critical",
  "path": "env:GITHUB_TOKEN",
  "metadata": {}
}
```

The fingerprint allows you to track and deduplicate findings without exposing the secret.

## False Positives

Detectors include safeguards to reduce false positives:

- **Generic API Key** - Filters placeholder values and environment variable references
- **SSH Keys** - Differentiates encrypted from unencrypted keys
- **Cloud Credentials** - Uses specific prefixes and formats per provider

If you encounter false positives, please [open an issue](https://github.com/boostsecurityio/bagel/issues) with sanitized examples.

## Adding Custom Detectors

Bagel's detector system is extensible. See the [source code](https://github.com/boostsecurityio/bagel/tree/main/internal/detector) for implementation examples.
