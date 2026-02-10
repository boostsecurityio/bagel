---
title: "NPM Probe"
slug: npm
url: /probes/npm/
---

The **npm** probe examines your NPM and Yarn configuration files for insecure settings.

## What It Checks

| Check | Finding ID | Severity | Description |
|-------|-----------|----------|-------------|
| SSL Verification | `npm-ssl-verify-disabled` | High | strict-ssl=false |
| Insecure Registry | `npm-insecure-registry` | High | HTTP registry configured |
| Always Auth | `npm-always-auth-enabled` | Low | always-auth=true (informational) |

## Files Scanned

- `~/.npmrc`
- `~/.yarnrc`
- Project-level `.npmrc` and `.yarnrc` files

## Findings

### npm-ssl-verify-disabled

**Severity:** High

NPM is configured to skip SSL certificate verification (`strict-ssl=false`). This makes you vulnerable to man-in-the-middle attacks when installing packages.

**Why This Is Dangerous:**

Best practice especially inside corporate networks with custom registries

**Remediation:**

Remove the setting from your `.npmrc`:

```bash
# Remove the line "strict-ssl=false" from ~/.npmrc
# Or run:
npm config delete strict-ssl
```

If you need to use a corporate registry with a self-signed certificate, configure the CA certificate instead:

```bash
npm config set cafile /path/to/corporate-ca.crt
```

---

### npm-insecure-registry

**Severity:** High

NPM is configured to use an HTTP (non-HTTPS) registry. Package downloads are not encrypted and could be intercepted or modified.

**Why This Is Dangerous:**

Without TLS encryption:
- Credentials may be transmitted in plain text
- Package contents can be modified in transit
- You have no verification that packages came from the registry

**Remediation:**

Update your registry configuration to use HTTPS:

```bash
# Check current registry
npm config get registry

# Set to HTTPS
npm config set registry https://registry.npmjs.org/

# For scoped packages
npm config set @mycompany:registry https://npm.mycompany.com/
```

If your internal registry doesn't support HTTPS, work with your infrastructure team to enable TLS.

---

### npm-always-auth-enabled

**Severity:** Low

NPM is configured with `always-auth=true`, which sends authentication credentials with every request, even to public registries.

**Why This Is Noted:**

While `always-auth` can be legitimate for private registries, it:
- May leak tokens to registries that don't need them
- Increases the risk if `.npmrc` is accidentally committed

**Remediation:**

If you don't need always-auth:

```bash
npm config delete always-auth
```

For private registries, configure auth per-registry instead:

```ini
# ~/.npmrc
@mycompany:registry=https://npm.mycompany.com/
//npm.mycompany.com/:_authToken=${NPM_TOKEN}
```

## Secret Detection

The NPM probe also scans `.npmrc` and `.yarnrc` files for embedded secrets using all registered detectors. This can catch:

- NPM authentication tokens (`npm_*`)
- Registry passwords in URLs
- Bearer tokens in auth configurations

## Best Practices

1. **Never commit .npmrc with tokens** - Use environment variables:
   ```ini
   //registry.npmjs.org/:_authToken=${NPM_TOKEN}
   ```

2. **Use HTTPS registries only** - Never use HTTP for package registries

3. **Scope private registry auth** - Don't send auth to public registries:
   ```ini
   @mycompany:registry=https://npm.mycompany.com/
   //npm.mycompany.com/:_authToken=${NPM_TOKEN}
   ```

4. **Review package-lock.json** - Ensure resolved URLs use HTTPS

5. **Use npm audit** - Regularly check for vulnerable dependencies:
   ```bash
   npm audit
   npm audit fix
   ```
