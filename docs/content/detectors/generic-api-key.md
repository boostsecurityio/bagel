---
title: "Generic API Key Detector"
slug: generic-api-key
url: /detectors/generic-api-key/
---

The **generic-api-key** detector identifies API keys and secrets that don't match specific provider patterns but appear to be credentials based on context and entropy.

## How It Works

The detector uses a two-stage approach:

1. **Pattern Matching** - Looks for keyword + assignment + value patterns
2. **Entropy Analysis** - Validates matches have sufficient randomness

## Pattern Matched

The detector looks for patterns like:
```
KEYWORD[context]SEPARATOR[value]
```

### Keywords Recognized
- `access`, `auth`, `api`
- `credential`, `creds`
- `key`, `password`
- `secret`, `token`

### Separators Recognized
- `=`, `:`, `=>`
- `||`, `?=`

### Example Matches
```bash
api_key=sk_live_abc123xyz789...
auth_token: "eyJhbGciOiJIUzI1..."
SECRET_KEY => 'long-random-string-here'
```

## Entropy Threshold

Matches must have Shannon entropy >= 3.5 bits per character to be reported.

**Shannon entropy** measures randomness. Higher entropy indicates more random (likely credential) values:

| Value | Entropy | Reported? |
|-------|---------|-----------|
| `password123` | ~2.8 | No |
| `aB3$xY9!mK2` | ~3.6 | Yes |
| `ghp_xxxxxxxxxxxx` | ~4.0+ | Yes |

## Exclusion Patterns

The detector filters out common false positives:

- **Placeholders:** `your-api-key`, `example-token`, `test-secret`
- **Environment references:** `$API_KEY`, `${TOKEN}`
- **Common values:** `true`, `false`, `null`, `localhost`
- **Patterns:** `xxxxx`, `*****`, `...`

## Finding Details

| Attribute | Value |
|-----------|-------|
| Finding ID | `generic-api-key` |
| Severity | **High** |

## Example Finding

```json
{
  "id": "generic-api-key",
  "fingerprint": "abcdef123456...",
  "probe": "env",
  "severity": "high",
  "title": "Generic API Key Detected",
  "message": "A generic API key or high-entropy secret was detected in file:/Users/dev/.bashrc (entropy: 4.23).",
  "path": "file:/Users/dev/.bashrc",
  "metadata": {
    "detector_name": "generic-api-key",
    "token_type": "generic-api-key",
    "entropy": "4.23"
  }
}
```

## Why This Matters

Generic secrets can include:

- Internal API keys
- Third-party service credentials
- Database passwords
- Webhook secrets
- Encryption keys

Any high-entropy secret warrants investigation.

## Remediation

### 1. Identify the Secret

Check what service or system the secret is for by examining the context:

```bash
# In shell config
export STRIPE_SECRET_KEY="sk_live_..."

# In .env file
DATABASE_PASSWORD="complex-password-here"
```

### 2. Rotate if Necessary

If the secret may have been exposed:
- Generate a new secret in the service's dashboard
- Update your secure storage
- Remove from shell history and config files

### 3. Store Securely

```bash
# Use a secrets manager
export API_KEY=$(vault kv get -field=key secret/myapp)

# Or encrypted .env with direnv
# .envrc
dotenv_if_exists .env.local
```

### 4. Avoid Hardcoding

```bash
# BAD
export API_KEY="sk_live_abc123..."

# GOOD - reference from secure storage
export API_KEY=$(op read "op://Private/MyService/api-key")
```

## Reducing False Positives

If you're seeing false positives, check if the matched value:

1. **Is a placeholder** - Use obvious placeholder names:
   ```bash
   export API_KEY="<your-api-key-here>"  # Won't match
   ```

2. **References environment** - Use variable syntax:
   ```bash
   API_KEY=$REAL_API_KEY  # Won't match (low entropy)
   ```

3. **Is in a comment** - Comments may still match, move to documentation

## When to Investigate

Even if a generic finding seems like a false positive, consider:

- Is this value actually sensitive?
- Should it be in this file at all?
- Could it become sensitive if the format changes?

It's better to investigate and dismiss than to miss a real credential.

## Related

- [AI Service Detector]({{< relref "/detectors/ai-service" >}}) - Specific AI API key patterns
- [GitHub Token Detector]({{< relref "/detectors/github-token" >}}) - GitHub-specific tokens
- [Cloud Credentials Detector]({{< relref "/detectors/cloud-credentials" >}}) - Cloud provider patterns
