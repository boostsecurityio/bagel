---
title: "JetBrains Probe"
slug: jetbrains
url: /probes/jetbrains/
---

The **jetbrains** probe scans JetBrains IDE (IntelliJ, PyCharm, GoLand, WebStorm, etc.) project configuration files for exposed secrets.

## What It Checks

The probe examines JetBrains workspace files and extracts:

- **Environment variables** from run configurations
- **Program arguments** from run configurations

These are then scanned by all secret detectors.

## Files Scanned

- `.idea/workspace.xml`

The probe parses XML workspace files looking for `RunManager` components.

## Why This Matters

JetBrains IDEs store run configurations in XML files. Developers frequently put secrets in these configurations for local testing:

- Database connection strings
- API keys for testing
- Service account credentials
- Authentication tokens

## Common Finding Sources

| Configuration Type | Common Secrets |
|-------------------|----------------|
| Environment Variables | API keys, tokens, passwords |
| Program Arguments | Auth tokens, connection strings |
| Database Connections | Passwords, connection URLs |
| HTTP Client | Bearer tokens, API keys |

## Example Finding

```json
{
  "id": "ai-service-openai-api-key",
  "probe": "jetbrains",
  "severity": "critical",
  "title": "AI Service API Key Detected (OpenAI API Key)",
  "message": "An OpenAI API Key was detected in file:/Users/dev/myproject/.idea/workspace.xml.",
  "path": "file:/Users/dev/myproject/.idea/workspace.xml",
  "metadata": {
    "config_name": "Run Server"
  }
}
```

## Remediation

### 1. Remove Secrets from Run Configurations

Open your IDE and edit the run configuration:
1. Run -> Edit Configurations
2. Select the configuration with secrets
3. Remove hardcoded values from Environment Variables

### 2. Exclude Workspace Files from Git

Add to `.gitignore`:
```gitignore
# JetBrains
.idea/workspace.xml
.idea/tasks.xml
.idea/usage.statistics.xml
.idea/dictionaries
.idea/shelf

# Or exclude entire .idea folder (lose shared settings)
# .idea/
```

## Best Practices

1. **Never commit workspace.xml:**
   ```gitignore
   .idea/workspace.xml
   ```

2. **Use run configuration templates:**
   - Create shared configs without secrets
   - Each developer adds secrets locally

3.**Use IDE's "Store as project file" carefully:**
   - Check what gets saved before committing

4.**Review before commits:**
   ```bash
   git diff --staged .idea/
   ```

## Related Probes

- [Environment Probe]({{< relref "/probes/env" >}}) - Checks environment variables
- [Shell History Probe]({{< relref "/probes/shell-history" >}}) - Checks command history
