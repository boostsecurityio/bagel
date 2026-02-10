---
title: "Defense Strategies"
slug: defense-strategies
url: /threats/defense-strategies/
---

Defending against info stealers requires layering multiple security measures. This guide covers practical defenses.

## Credential Hygiene

The most important defense is reducing what can be stolen.

### Use Short-Lived Credentials
Limit time window for the ability to use stolen credentials by setting shoter session lengths for credentials when possible. Ideally usage of a second factor to refresh a credential should be required for increased security.


### Minimize Permissions

Request only what you need:

```bash
# BAD: All permissions
gh auth login --scopes "repo,admin:org,gist,user,delete_repo,write:packages"

# GOOD: Minimum needed
gh auth login --scopes "repo"
```

### Secure Storage

Never store credentials in plaintext on your machine. Leverage OS keyrings or secret management tools to protect your credentials from theft and only retrieve them when needed. For maximum security, use hardware-backed storage where available(MacOS secure enclave, TPM, hardware security keys).
Examples include:
- macOS Keychain (https://secretive.dev/)
- Linux/Windows TPM (Windows Hello)
- Password managers (1Password, Bitwarden, etc.)

### Separate Identities

Use different credentials for:
- Personal projects vs. work
- Production vs. development
- High-security vs. general access

### IDE Extensions

- Only install extensions from verified publishers
- Review extension permissions
- Keep extensions updated
- Remove unused extensions

## How Bagel Helps

Bagel fits into your defense strategy by providing visibility:

### Proactive Detection

Run Bagel regularly to find:
- Unencrypted SSH keys
- Hardcoded credentials in configs
- Insecure tool configurations
- Exposed secrets in shell history
