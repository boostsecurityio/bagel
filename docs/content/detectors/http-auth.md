---
title: "HTTP Authentication Detector"
slug: http-auth
url: /detectors/http-auth/
---

The **http-authentication** detector identifies HTTP authentication credentials in various formats.

## Patterns Detected

| Pattern | Finding ID | Description |
|---------|-----------|-------------|
| Bearer Token | `http-auth-bearer-token` | `Authorization: Bearer <token>` |
| Basic Auth | `http-auth-basic-auth` | `Authorization: Basic <base64>` |
| API Key Header | `http-auth-api-key-header` | `X-API-Key: <key>` |
| URL Auth | `http-auth-basic-auth-url` | `http://user:pass@host` |

All findings have **Critical** severity.

## Pattern Details

### Bearer Token
```
Authorization:\s*(?:Bearer|(?:Api-)?Token)\s+([\w=~@.+/-]{16,})
```

Matches:
- `Authorization: Bearer eyJhbGciOi...`
- `Authorization: Token ghp_xxxx...`
- `Authorization: Api-Token xxx...`

### Basic Authentication
```
Authorization:\s*Basic\s+([a-zA-Z0-9+/]{16,}={0,2})
```

Matches base64-encoded `username:password` in Basic auth headers.

### API Key Headers
```
(?:X-)?(?:API|Api)-?(?:Key|Token):\s*([\w=~@.+/-]{16,})
```

Matches:
- `X-API-Key: xxx...`
- `Api-Key: xxx...`
- `X-Api-Token: xxx...`

### URL Authentication
```
(?:https?|ftp)://([a-zA-Z0-9_.-]{3,}):([^@\s]{3,})@
```

Matches credentials embedded in URLs:
- `https://user:password@api.example.com`
- `http://admin:secret@internal.service`

## Example Findings

### Bearer Token in Shell History

```json
{
  "id": "http-auth-bearer-token",
  "probe": "shell_history",
  "severity": "critical",
  "title": "HTTP Authentication Credential Detected (Bearer Token in Authorization Header)",
  "message": "A Bearer Token in Authorization Header was detected in file:/Users/dev/.zsh_history.",
  "path": "file:/Users/dev/.zsh_history"
}
```

### Basic Auth in URL

```json
{
  "id": "http-auth-basic-auth-url",
  "probe": "env",
  "severity": "critical",
  "title": "HTTP Authentication Credential Detected (Basic Authentication in URL)",
  "message": "A Basic Authentication in URL was detected in environment variable DATABASE_URL.",
  "path": "env:DATABASE_URL"
}
```

## Common Exposure Scenarios

### curl Commands in History

```bash
# BAD - Token in command history
curl -H "Authorization: Bearer sk-xxx..." https://api.openai.com/v1/completions
```

### Scripts with Hardcoded Auth

```bash
# BAD - Credentials in script
wget --user=admin --password=secret https://internal.example.com/
```

### Database URLs

```bash
# BAD - Password in connection string
DATABASE_URL="postgresql://user:password@localhost/db"
```

## Remediation

### For curl/wget Commands

Use environment variables or files:

```bash
# GOOD - Token from environment
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/

# GOOD - Credentials from file
curl --netrc-file ~/.netrc https://api.example.com/
```

### For Basic Auth URLs

Use authentication configuration instead of URL embedding:

```bash
# BAD
DATABASE_URL="postgresql://user:password@localhost/db"

# GOOD - Separate credentials
DATABASE_URL="postgresql://localhost/db"
DATABASE_USER="user"
DATABASE_PASSWORD=$(vault read -field=password secret/db)
```

### For API Key Headers

Use secure secret injection:

```bash
# GOOD - From secret manager
curl -H "X-API-Key: $(op read 'op://Private/API/key')" https://api.example.com/
```

### Clean Shell History

If you've used auth in commands:

```bash
# Find problematic commands
history | grep -i "authorization\|bearer\|basic\|password"

# Edit history file
vim ~/.bash_history  # or ~/.zsh_history

# Or clear and reload
history -c
```

## Best Practices

1. **Never pass credentials as arguments:**
   ```bash
   # BAD
   curl -u "user:password" ...

   # GOOD - Will prompt
   curl -u "user" ...
   ```

2. **Use .netrc for HTTP auth:**
   ```
   # ~/.netrc (chmod 600)
   machine api.example.com
   login myuser
   password mypassword
   ```

3. **Avoid credentials in URLs:**
   ```bash
   # BAD
   git clone https://user:token@github.com/org/repo

   # GOOD
   git clone https://github.com/org/repo
   # Configure credential helper separately
   ```

4. **Use environment variables or files:**
   ```bash
   # From environment
   curl -H "Authorization: Bearer $TOKEN" ...

   # From file
   curl -H @headers.txt ...
   ```

5. **Configure history to ignore sensitive commands:**
   ```bash
   # Ignore commands starting with space
   HISTCONTROL=ignorespace  # bash
   setopt HIST_IGNORE_SPACE  # zsh
   ```

## Related

- [Shell History Probe]({{< relref "/probes/shell-history" >}}) - Checks command history
- [JWT Detector]({{< relref "/detectors/jwt" >}}) - Detects JWT tokens specifically
