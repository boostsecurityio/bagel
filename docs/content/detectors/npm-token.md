---
title: "NPM Token Detector"
slug: npm-token
url: /detectors/npm-token/
---

The **npm-token** detector identifies NPM registry authentication tokens.

## Pattern Detected

| Pattern | Finding ID | Description |
|---------|-----------|-------------|
| `npm_[a-z0-9]{36}` | `npm-token-npm-auth-token` | NPM Authentication Token |

Finding severity: **Critical**

## Pattern Details

```
npm_[a-z0-9]{36}
```

NPM automation tokens follow a consistent format:
- Prefix: `npm_`
- 36 lowercase alphanumeric characters

## Example Finding

```json
{
  "id": "npm-token-npm-auth-token",
  "fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "probe": "npm",
  "severity": "critical",
  "title": "NPM Token Detected (NPM Authentication Token)",
  "message": "An NPM Authentication Token was detected in file:/Users/dev/.npmrc. This credential provides access to NPM packages and registries.",
  "path": "file:/Users/dev/.npmrc",
  "metadata": {
    "detector_name": "npm-token",
    "token_type": "npm-auth-token"
  }
}
```

## Impact of Exposure

A compromised NPM token allows attackers to:

### Package Publishing
- Publish malicious versions of your packages
- Add backdoors to widely-used libraries
- Typosquatting with similar package names

### Package Access
- Download private packages
- Access organization packages
- View package metadata

### Supply Chain Attacks
- npm packages have deep dependency trees
- One compromised package affects thousands of projects
- Real-world examples: event-stream, ua-parser-js

## Remediation

### 1. Revoke the Token Immediately

```bash
# List your tokens
npm token list

# Revoke the compromised token
npm token revoke <token-id>
```

Or via the web:
1. Go to [npmjs.com](https://www.npmjs.com)
2. Account -> Access Tokens
3. Delete the compromised token

### 2. Audit Package Activity

Check if unauthorized changes were made:

```bash
# Check package versions
npm view <package-name> versions

# Check publish history
npm view <package-name> time
```

Review recent npm activity in your account settings.

### 3. Create a New Token

```bash
# Create automation token (for CI/CD)
npm token create --read-only  # For installing only
npm token create --cidr=x.x.x.x/x  # With IP restrictions
```

### 4. Store Securely

```bash
# Use environment variables
export NPM_TOKEN=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Reference in .npmrc
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

Never commit tokens to version control.

## Token Types

NPM supports different token types with varying permissions:

| Type | Permissions | Use Case |
|------|------------|----------|
| Publish | Read, Write, Publish | Local development |
| Automation | Read, Write, Publish | CI/CD pipelines |
| Read-only | Read only | Installing packages |
| Granular | Custom per-package | Fine-grained control |

### Recommendations

1. **Use read-only tokens** for CI/CD that only installs packages
2. **Use automation tokens** for publishing pipelines
3. **Use granular tokens** to limit scope to specific packages
4. **Add CIDR restrictions** to limit token use by IP range

## Best Practices

1. **Never commit .npmrc with tokens:**
   ```gitignore
   # .gitignore
   .npmrc
   ```

2. **Use environment variable interpolation:**
   ```ini
   # .npmrc (safe to commit)
   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
   ```

3. **Scope tokens to registries:**
   ```ini
   # Only send token to specific registry
   @mycompany:registry=https://npm.mycompany.com/
   //npm.mycompany.com/:_authToken=${PRIVATE_NPM_TOKEN}
   ```

4. **Use CI/CD secrets management:**
   ```yaml
   # GitHub Actions
   - name: Setup Node
     uses: actions/setup-node@v4
     with:
       node-version: '20'
       registry-url: 'https://registry.npmjs.org'
     env:
       NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
   ```

5. **Enable 2FA for publishing:**
   - Require 2FA for publish operations
   - Prevents token-only publishing

6. **Regular token rotation:**
   - Rotate tokens periodically
   - Immediately rotate after any potential exposure

## Checking Token Permissions

```bash
# See what permissions your token has
npm whoami
npm token list
```

## Related

- [NPM Probe]({{< relref "/probes/npm" >}}) - Checks NPM configuration security
- [Generic API Key Detector]({{< relref "/detectors/generic-api-key" >}}) - Catches other secret patterns
