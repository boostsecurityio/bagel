---
title: "Git Probe"
slug: git
url: /probes/git/
---

The **git** probe examines your global Git configuration for insecure settings that could expose you to attacks.

## What It Checks

| Check | Finding ID | Severity | Description |
|-------|-----------|----------|-------------|
| SSL Verification | `git-ssl-verify-disabled` | High | http.sslVerify=false |
| SSH Host Key Checking | `git-ssh-no-host-key-check` | High | StrictHostKeyChecking disabled in core.sshcommand |
| SSH Known Hosts | `git-ssh-no-known-hosts` | High | UserKnownHostsFile disabled |
| Credential Storage | `git-credential-plaintext` | High | credential.helper=store (plaintext) |
| Dangerous Protocols | `git-dangerous-protocol` | Medium | ext/fd/file protocols allowed |
| Object Verification | `git-fsck-disabled` | Medium | transfer/fetch/receive.fsckobjects=false |
| Proxy Configuration | `git-proxy-configured` | Low | http.proxy or https.proxy configured |
| Custom Hooks Path | `git-custom-hooks-path` | Medium | core.hookspath configured |

## Findings

### git-ssl-verify-disabled

**Severity:** High

Git is configured to skip SSL certificate verification (`http.sslVerify=false`). This makes you vulnerable to man-in-the-middle attacks when cloning or pulling from HTTPS repositories.

**Remediation:**
```bash
git config --global http.sslVerify true
```

If you're having certificate issues with a corporate proxy or self-signed cert, configure the CA bundle instead:
```bash
git config --global http.sslCAInfo /path/to/ca-bundle.crt
```

---

### git-ssh-no-host-key-check

**Severity:** High

Git is configured to skip SSH host key verification via `core.sshcommand`. This makes you vulnerable to man-in-the-middle attacks.

**Remediation:**

Remove the insecure SSH options from your Git config:
```bash
git config --global --unset core.sshcommand
```

Or configure SSH properly with host key verification:
```bash
git config --global core.sshcommand "ssh -o StrictHostKeyChecking=yes"
```

---

### git-ssh-no-known-hosts

**Severity:** High

Git is configured to ignore the SSH known_hosts file (`UserKnownHostsFile=/dev/null`), preventing host key verification.

**Remediation:**

Remove the insecure configuration:
```bash
git config --global --unset core.sshcommand
```

---

### git-credential-plaintext

**Severity:** High

Git is configured to store credentials in plaintext on disk using `credential.helper=store`. The credentials file (`~/.git-credentials`) can be easily accessed by any process.

**Remediation:**

Use a secure credential helper instead:

**macOS:**
```bash
git config --global credential.helper osxkeychain
```

**Linux:**
```bash
# Use libsecret (GNOME)
git config --global credential.helper libsecret

# Or use cache with timeout
git config --global credential.helper 'cache --timeout=3600'
```

**Windows:**
```powershell
git config --global credential.helper wincred
```

---

### git-dangerous-protocol

**Severity:** Medium

Git is configured to allow dangerous protocols (`ext`, `fd`, or `file`) which can be used to execute arbitrary commands or access local files.

**Remediation:**

Disable the dangerous protocol:
```bash
git config --global protocol.ext.allow never
git config --global protocol.fd.allow never
git config --global protocol.file.allow user
```

---

### git-fsck-disabled

**Severity:** Medium

Git is configured to skip object verification (`transfer.fsckobjects=false`, `fetch.fsckobjects=false`, or `receive.fsckobjects=false`). This could allow corrupted or malicious objects to be accepted.

**Remediation:**

Enable object verification:
```bash
git config --global transfer.fsckobjects true
git config --global fetch.fsckobjects true
git config --global receive.fsckobjects true
```

---

### git-proxy-configured

**Severity:** Low

Git is configured to use a proxy. While this may be legitimate in corporate environments, ensure the proxy is trusted as it can intercept all Git traffic.

**Remediation:**

If the proxy is not needed:
```bash
git config --global --unset http.proxy
git config --global --unset https.proxy
```

---

### git-custom-hooks-path

**Severity:** Medium

Git is configured with a custom hooks directory (`core.hookspath`). This could be used to execute malicious code during Git operations.

**Remediation:**

Review the configured hooks path and ensure all hooks are trusted:
```bash
git config --global --get core.hookspath
ls -la $(git config --global --get core.hookspath)
```

If not needed, remove the configuration:
```bash
git config --global --unset core.hookspath
```

## Secret Detection

The git probe also scans Git configuration values for embedded secrets using all registered detectors. This can catch things like:

- API tokens in credential helpers
- Passwords in proxy URLs
- Tokens in custom configuration values
