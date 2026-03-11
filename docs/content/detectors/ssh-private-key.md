---
title: "SSH Private Key Detector"
slug: ssh-private-key
url: /detectors/ssh-private-key/
---

The **ssh-private-key** detector identifies SSH private keys and determines whether they are password-protected (encrypted).

## Detection Pattern

The detector matches PEM-formatted private keys:

```
-----BEGIN [TYPE] PRIVATE KEY-----
[base64 content]
-----END [TYPE] PRIVATE KEY-----
```

## Key Types Detected

| Key Type | Finding ID |
|----------|-----------|
| RSA | `ssh-private-key-rsa` |
| DSA | `ssh-private-key-dsa` |
| EC (ECDSA) | `ssh-private-key-ec` |
| OpenSSH | `ssh-private-key-openssh` |
| PKCS#8 | `ssh-private-key-pkcs8` |
| Encrypted | `ssh-private-key-encrypted` |

## Severity

| Key State | Severity | Rationale |
|-----------|----------|-----------|
| Unencrypted | **Critical** | Anyone with file access can use the key |
| Encrypted | **Low** | Key is password-protected |

## Encryption Detection

The detector checks for encryption indicators:

### Traditional PEM Format
- `-----BEGIN ENCRYPTED PRIVATE KEY-----`
- `Proc-Type: 4,ENCRYPTED` header
- `DEK-Info:` header with cipher info

### OpenSSH Format
Checks for base64-encoded cipher names:
- `YWVzMTI4LWN0cg` (aes128-ctr)
- `YWVzMjU2LWNiYw` (aes256-cbc)
- `YmNyeXB0` (bcrypt KDF)

If `bm9uZQ` (none) is found, the key is unencrypted.

## Example Findings

### Unencrypted Key (Critical)

```json
{
  "id": "ssh-private-key-rsa",
  "fingerprint": "sha256:...",
  "probe": "ssh",
  "severity": "critical",
  "title": "Unencrypted SSH Private Key Detected (RSA)",
  "message": "An unencrypted RSA SSH private key was detected in file:/Users/dev/.ssh/id_rsa. This key is NOT password-protected...",
  "path": "file:/Users/dev/.ssh/id_rsa",
  "metadata": {
    "key_type": "RSA",
    "is_encrypted": false
  }
}
```

### Encrypted Key (Low)

```json
{
  "id": "ssh-private-key-rsa",
  "fingerprint": "sha256:...",
  "probe": "ssh",
  "severity": "low",
  "title": "Encrypted SSH Private Key Detected (RSA)",
  "message": "An encrypted RSA SSH private key was detected in file:/Users/dev/.ssh/id_rsa. The key is password-protected...",
  "path": "file:/Users/dev/.ssh/id_rsa",
  "metadata": {
    "key_type": "RSA",
    "is_encrypted": true
  }
}
```

## Why Unencrypted Keys Are Critical

An unencrypted SSH private key can be used immediately by anyone who obtains the file:

- **Physical access** - Someone with access to your machine
- **Malware** - Info stealers specifically target SSH keys
- **Backup exposure** - Keys in unencrypted backups
- **Accidental commits** - Keys committed to git repositories

## Remediation

### Add Passphrase to Existing Key

```bash
# Add or change passphrase
ssh-keygen -p -f ~/.ssh/id_rsa

# You'll be prompted for:
# 1. Current passphrase (empty if none)
# 2. New passphrase
# 3. Confirm new passphrase
```

### Generate New Encrypted Key

```bash
# Ed25519 (recommended)
ssh-keygen -t ed25519 -C "your_email@example.com"

# RSA (if Ed25519 not supported)
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

You'll be prompted for a passphrase during generation.

### Using ssh-agent

To avoid typing your passphrase repeatedly:

```bash
# Start ssh-agent
eval $(ssh-agent)

# Add key (prompts for passphrase once)
ssh-add ~/.ssh/id_ed25519

# With timeout (1 hour)
ssh-add -t 3600 ~/.ssh/id_ed25519
```

**macOS Keychain Integration:**
```bash
# Add to Keychain
ssh-add --apple-use-keychain ~/.ssh/id_ed25519

# Configure to use Keychain automatically
# In ~/.ssh/config:
Host *
    UseKeychain yes
    AddKeysToAgent yes
```

### Key Management Best Practices

1. **Always use passphrases** - Protects keys at rest

2. **Use Ed25519** - More secure and faster than RSA:
   ```bash
   ssh-keygen -t ed25519
   ```

3. **Set appropriate permissions:**
   ```bash
   chmod 600 ~/.ssh/id_*
   chmod 700 ~/.ssh
   ```

4. **Use separate keys** for different purposes:
   - Personal GitHub
   - Work servers
   - Production access

5. **Rotate keys periodically** - Replace old keys, especially if they may have been exposed

6. **Use SSH certificates** for large-scale environments

## Related

- [SSH Probe]({{< relref "/probes/ssh" >}}) - Checks SSH configuration and key security
