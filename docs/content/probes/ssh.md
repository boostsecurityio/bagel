---
title: "SSH Probe"
slug: ssh
url: /probes/ssh/
---

The **ssh** probe examines your SSH configuration files and private keys for security issues.

## What It Checks

| Check | Finding ID | Severity | Description |
|-------|-----------|----------|-------------|
| Host Key Checking | `ssh-strict-host-key-checking-disabled` | High | StrictHostKeyChecking=no |
| Known Hosts | `ssh-known-hosts-disabled` | High | UserKnownHostsFile=/dev/null |
| Agent Forwarding | `ssh-forward-agent-enabled` | Medium | ForwardAgent=yes |
| Key Permissions | `ssh-key-insecure-permissions` | High | Private key not 0600 |
| Unencrypted Keys | `ssh-private-key-*` | Critical/Low | Detected by SSH key detector |

## Files Scanned

- `~/.ssh/config`
- `~/.ssh/*.key`, `~/.ssh/id_*`
- Platform-specific SSH config locations

## Findings

### ssh-strict-host-key-checking-disabled

**Severity:** High

SSH config disables host key verification (`StrictHostKeyChecking=no`). This makes you vulnerable to man-in-the-middle attacks when connecting to SSH servers.

**Remediation:**

Remove or change the setting in your SSH config (`~/.ssh/config`):

```
# Change from:
Host *
    StrictHostKeyChecking no

# To:
Host *
    StrictHostKeyChecking ask
```

Or remove the line entirely to use the default (ask).

---

### ssh-known-hosts-disabled

**Severity:** High

SSH config disables the known_hosts file by pointing it to `/dev/null` (or `nul` on Windows). This prevents SSH from verifying host keys.

**Remediation:**

Remove the `UserKnownHostsFile` directive or set it to the default:

```
# Remove this line:
UserKnownHostsFile /dev/null

# Or use default location:
UserKnownHostsFile ~/.ssh/known_hosts
```

---

### ssh-forward-agent-enabled

**Severity:** Medium

SSH agent forwarding is enabled (`ForwardAgent=yes`). This can be a security risk if you connect to untrusted hosts, as they could use your forwarded keys to authenticate to other servers.

**Remediation:**

Disable agent forwarding globally and enable only for specific trusted hosts:

```
# Disable globally
Host *
    ForwardAgent no

# Enable only for trusted hosts
Host trusted-jumpbox.example.com
    ForwardAgent yes
```

Better alternatives to agent forwarding:
- Use `ProxyJump` (-J) for jump hosts
- Use `ssh-add -c` to require confirmation for key usage

---

### ssh-key-insecure-permissions

**Severity:** High

SSH private key has overly permissive file permissions. SSH keys should only be readable by the owner (permissions `0600` or `0400`).

**Remediation:**

**macOS/Linux:**
```bash
chmod 600 ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_ed25519
# Or for all private keys:
chmod 600 ~/.ssh/id_*
chmod 600 ~/.ssh/*.key
```

**Windows:**
Windows uses ACLs instead of Unix permissions. Ensure the key file is only readable by your user account:

1. Right-click the key file -> Properties
2. Security tab -> Advanced
3. Disable inheritance
4. Remove all permissions except your user account
5. Your user should have Read permission only

> **Note:** This check is skipped on Windows, which uses ACLs instead of Unix permission bits.

---

### ssh-private-key-* (Unencrypted Keys)

**Severity:** Critical (unencrypted) / Low (encrypted)

The SSH probe uses the [SSH Private Key Detector]({{< relref "/detectors/ssh-private-key" >}}) to identify private keys and determine if they are encrypted.

**Remediation:**

Add a passphrase to your SSH key:

```bash
# Add passphrase to existing key
ssh-keygen -p -f ~/.ssh/id_rsa

# When prompted, enter a strong passphrase
```

Consider using `ssh-agent` to avoid entering your passphrase repeatedly:

```bash
# Start ssh-agent
eval $(ssh-agent)

# Add key (will prompt for passphrase once)
ssh-add ~/.ssh/id_rsa
```

## Best Practices

1. **Use Ed25519 keys** - More secure and faster than RSA
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```

2. **Always use passphrases** - Protects keys if your disk is compromised

3. **Use ssh-agent** - Caches decrypted keys in memory with timeout
   ```bash
   ssh-add -t 3600 ~/.ssh/id_ed25519  # 1 hour timeout
   ```
Or use your OS's keychain integration, TPM or hardware tokens (YubiKey, etc.) for increased protection.

4. **Avoid agent forwarding** - Use ProxyJump instead
   ```bash
   ssh -J jumphost.example.com finalhost.example.com
   ```

5. **Review known_hosts regularly** - Remove entries for decommissioned servers
