---
title: "GitHub Token Detector"
slug: github-token
url: /detectors/github-token/
---

The **github-token** detector identifies various types of GitHub authentication tokens.

## Token Types Detected

| Token Prefix | Finding ID | Description |
|-------------|-----------|-------------|
| `ghp_` | `github-token-classic-pat` | Classic Personal Access Token |
| `github_pat_` | `github-token-fine-grained-pat` | Fine-grained Personal Access Token |
| `gho_` | `github-token-oauth-token` | OAuth Access Token |
| `ghu_` | `github-token-app-user-token` | GitHub App User-to-Server Token |
| `ghs_` | `github-token-app-server-token` | GitHub App Server-to-Server Token |
| `ghr_` | `github-token-refresh-token` | GitHub Refresh Token |

All findings have **Critical** severity.

## Pattern Details

### Classic PAT (`ghp_`)
```
ghp_[A-Za-z0-9]{36}
```
The classic personal access token format. These tokens provide access based on user-defined scopes.

### Fine-grained PAT (`github_pat_`)
```
github_pat_\w{82}
```
Newer fine-grained tokens with repository-level and permission-specific access.

### OAuth Token (`gho_`)
```
gho_[A-Za-z0-9]{36}
```
OAuth access tokens issued during the OAuth web flow.

### App User Token (`ghu_`)
```
ghu_[A-Za-z0-9]{36}
```
User-to-server tokens from GitHub Apps acting on behalf of users.

### App Server Token (`ghs_`)
```
ghs_[A-Za-z0-9]{36}
```
Server-to-server tokens from GitHub Apps acting as themselves.

### Refresh Token (`ghr_`)
```
ghr_[A-Za-z0-9]{36}
```
Refresh tokens used to obtain new access tokens.

## Example Finding

```json
{
  "id": "github-token-classic-pat",
  "probe": "env",
  "severity": "critical",
  "title": "GitHub Token Detected (Classic Personal Access Token)",
  "message": "A GitHub Classic Personal Access Token was detected in environment variable GITHUB_TOKEN.",
  "path": "env:GITHUB_TOKEN",
  "metadata": {
    "detector_name": "github-token",
    "token_type": "classic-pat",
    "description": "Classic Personal Access Token",
    "fingerprint": "sha256:..."
  }
}
```

## What Attackers Can Do

With a compromised GitHub token, attackers can:

| Token Type | Potential Impact |
|-----------|------------------|
| Classic PAT | Access repos, create commits, manage settings (based on scopes) |
| Fine-grained PAT | Limited repository/permission access |
| OAuth Token | Act as the user within granted scopes |
| App User Token | Access resources the app is authorized for |
| App Server Token | Access installation resources |
| Refresh Token | Obtain new access tokens |

## Remediation

### 1. Revoke the Token Immediately

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Find the compromised token
3. Click **Delete** or **Revoke**

For app tokens, revoke via the GitHub App settings.

### 2. Audit Recent Activity

Check what the token may have accessed:
- Review [Security Log](https://github.com/settings/security-log)
- Check repository activity
- Review organization audit logs (if applicable)

### 3. Create a New Token

When creating a replacement:

**For Classic PATs:**
- Use minimal scopes
- Set an expiration date
- Consider switching to fine-grained PATs

**For Fine-grained PATs:**
- Limit to specific repositories
- Grant minimal permissions
- Set short expiration

### 4. Store Securely

```bash
# Use environment variables (not hardcoded)
export GITHUB_TOKEN=$(op read "op://Private/GitHub/token")

# Or use gh CLI's credential storage
gh auth login
gh auth setup-git
```

## Best Practices

1. **Prefer fine-grained PATs** - More restrictive than classic tokens

2. **Set expiration dates** - Tokens should expire and be rotated

3. **Use minimal scopes** - Only grant what's needed

4. **Use GitHub Apps for automation** - Better than personal tokens for CI/CD

5. **Never commit tokens** - Use environment variables or secret managers:
   ```bash
   # .gitignore
   .env
   .env.local
   ```

6. **Enable token scanning** - GitHub will alert you if tokens are committed

## Related

- [GitHub CLI Probe]({{< relref "/probes/github-cli" >}}) - Checks for active gh authentication
- [GitHub Token Expiration](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation)
