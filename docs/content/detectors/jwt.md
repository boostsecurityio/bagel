---
title: "JWT Detector"
slug: jwt
url: /detectors/jwt/
---

The **jwt** detector identifies JWT and JWE tokens in scanned content.

## Token Types Detected

| Type | Finding ID | Format |
|------|-----------|--------|
| JWT | `jwt-jwt-token` | `header.payload.signature` (3 parts) |
| JWE | `jwt-jwe-token` | `header.enc_key.iv.ciphertext.tag` (5 parts) |

All findings have **Critical** severity.

## Pattern Details

### JWT Token
```
ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+
```

JWTs have three base64url-encoded parts:
1. **Header** - Algorithm and token type
2. **Payload** - Claims (user data, expiration, etc.)
3. **Signature** - Cryptographic signature

The header always starts with `ey` because it's a JSON object (`{"` encodes to `eyJ`).

### JWE Token
```
ey[A-Za-z0-9-_]+(?:\.[A-Za-z0-9-_]+){4}
```

JWEs have five parts:
1. **Header** - Encryption algorithm info
2. **Encrypted Key** - Content encryption key
3. **Initialization Vector** - Random IV
4. **Ciphertext** - Encrypted payload
5. **Authentication Tag** - Integrity check

## Example Finding

```json
{
  "id": "jwt-jwt-token",
  "probe": "shell_history",
  "severity": "critical",
  "title": "JWT Token Detected (JWT Token)",
  "message": "A JWT Token was detected in file:/Users/dev/.zsh_history. JWT tokens in plain text may be exposed in logs...",
  "path": "file:/Users/dev/.zsh_history",
  "metadata": {
    "detector_name": "jwt",
    "token_type": "jwt-token",
    "fingerprint": "sha256:..."
  }
}
```

## Why JWTs Are Critical

### Session Tokens
JWTs are commonly used as session tokens. A stolen JWT allows an attacker to:
- Impersonate the user
- Access protected resources
- Perform actions as the user until expiration

### Long-Lived Tokens
Many JWTs have long expiration times (hours, days, or longer), extending the attack window.

### Self-Contained
JWTs contain claims that servers trust without database lookup, making revocation difficult.

## Decoding JWTs

You can decode a JWT to understand what it contains (payload is not encrypted in standard JWTs):

```bash
# Using command line
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | \
  cut -d. -f2 | base64 -d 2>/dev/null

# Output: {"sub":"1234567890"}
```

Or use [jwt.io](https://jwt.io) (but never paste production tokens!).

## Remediation

### 1. Determine Token Validity

Check the token's expiration:
```bash
# Decode and check 'exp' claim
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .exp
# Convert timestamp: date -d @1234567890
```

If expired, the immediate risk is lower (but token reuse attacks may still apply).

### 2. Invalidate If Active

For valid tokens, invalidate server-side:
- Log out the session
- Add to a token blacklist
- Rotate signing keys (invalidates all tokens)

### 3. Clean Up Exposure

Remove the token from:
- Shell history
- Environment variables
- Log files
- Configuration files

### 4. Issue New Token

After cleanup, re-authenticate to get a fresh token.

## Best Practices

1. **Short expiration times:**
   ```
   exp: now + 15 minutes (access tokens)
   exp: now + 7 days (refresh tokens)
   ```

2. **Use refresh tokens:**
   - Short-lived access tokens
   - Longer refresh tokens stored securely
   - Refresh endpoint rotates both

3. **Don't log JWTs:**
   ```python
   # BAD
   logger.info(f"Request with token: {request.headers['Authorization']}")

   # GOOD
   logger.info("Authenticated request received")
   ```

4. **Store in memory, not localStorage:**
   ```javascript
   // BAD - accessible to XSS
   localStorage.setItem('token', jwt)

   // GOOD - httpOnly cookie or in-memory
   ```

5. **Use token binding:**
   - Bind tokens to client fingerprints
   - Validate binding on each request

6. **Implement token revocation:**
   - Maintain blacklist for logged-out tokens
   - Or use short expiration with refresh

## JWE vs JWT

| Feature | JWT | JWE |
|---------|-----|-----|
| Payload | Readable (base64) | Encrypted |
| Use case | Authentication, claims | Sensitive data transfer |
| Parts | 3 | 5 |

JWE provides confidentiality but is less common. Both should be treated as sensitive.

## Related

- [HTTP Auth Detector]({{< relref "/detectors/http-auth" >}}) - Detects Bearer tokens
- [Shell History Probe]({{< relref "/probes/shell-history" >}}) - Common JWT exposure vector
