---
title: "Shell History Probe"
slug: shell-history
url: /probes/shell-history/
---

The **shell_history** probe scans your shell command history files for accidentally exposed secrets.

## What It Checks

The probe reads shell history files and runs all secret detectors against each command line. This catches common mistakes like:

- Passing tokens as command-line arguments
- Using `curl` with authentication headers
- Running commands with embedded credentials

## Files Scanned

| Shell | History File |
|-------|-------------|
| Bash | `~/.bash_history` |
| Zsh | `~/.zsh_history` |
| Fish | `~/.local/share/fish/fish_history` |

The probe handles zsh's extended history format (`: timestamp:duration;command`).

## Common Finding Sources

Secrets often end up in shell history through:

| Pattern | Example |
|---------|---------|
| CLI authentication | `gh auth login --with-token ghp_xxx` |
| curl with headers | `curl -H "Authorization: Bearer sk-xxx" api.openai.com` |
| Environment exports | `export API_KEY=xxx` |
| Docker/kubectl | `docker login -p xxx` |
| Database connections | `mysql -pMyPassword` |

## Example Finding

```json
{
  "id": "ai-service-openai-api-key",
  "probe": "shell_history",
  "severity": "critical",
  "title": "AI Service API Key Detected (OpenAI API Key)",
  "message": "An OpenAI API Key was detected in file:/Users/dev/.zsh_history at line 1234.",
  "path": "file:/Users/dev/.zsh_history",
  "metadata": {
    "line_number": 1234
  }
}
```

## Remediation

### 1. Remove Secrets from History

**Bash:**
```bash
# Edit history file directly
vim ~/.bash_history
# Search for and delete lines containing secrets

# Or clear entire history (nuclear option)
history -c
rm ~/.bash_history
```

**Zsh:**
```bash
# Edit history file
vim ~/.zsh_history

# Or clear and restart
rm ~/.zsh_history
fc -p  # Clear in-memory history
```

### 2. Rotate Exposed Secrets

Any secret that appeared in your history should be considered compromised:

- **GitHub tokens:** Revoke and regenerate at github.com/settings/tokens
- **API keys:** Rotate in the respective service's dashboard
- **Passwords:** Change them immediately

### 3. Prevent Future Exposure

**Use environment variables instead of CLI arguments:**
```bash
# BAD
curl -H "Authorization: Bearer sk-xxx" https://api.openai.com/...

# GOOD
export OPENAI_API_KEY="sk-xxx"  # Set in secure .env file
curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/...
```

**Configure history to ignore sensitive commands:**

```bash
# ~/.bashrc or ~/.zshrc

# Don't save commands starting with space
HISTCONTROL=ignorespace  # bash
setopt HIST_IGNORE_SPACE  # zsh

# Now prefix sensitive commands with space
 export SECRET=xxx  # Note leading space - won't be saved
```

**Use CLI tools' built-in secure auth:**
```bash
# Instead of: gh auth login --with-token ghp_xxx
# Use interactive:
gh auth login

# Instead of: docker login -p xxx
# Use:
docker login  # Will prompt for password
# Or:
echo $DOCKER_TOKEN | docker login --username user --password-stdin
```

### 4. Exclude History from Backups

Ensure your shell history isn't backed up to cloud services:

```bash
# Add to Time Machine exclusions (macOS)
tmutil addexclusion ~/.bash_history
tmutil addexclusion ~/.zsh_history
```

## Best Practices

1. **Use a leading space** for sensitive commands:
   ```bash
   setopt HIST_IGNORE_SPACE  # zsh
   HISTCONTROL=ignorespace   # bash
    export SECRET=xxx  # Won't be saved
   ```

2. **Avoid inline credentials:**
   ```bash
   # BAD
   mysql -u root -pMyPassword

   # GOOD
   mysql -u root -p  # Will prompt
   ```

3. **Use credential helpers:**
   - `git credential-cache`
   - Docker credential helpers
   - Cloud CLI's built-in auth

4. **Read secrets from files:**
   ```bash
   # Instead of passing directly
   curl -H "Authorization: Bearer $(cat ~/.secrets/api-key)"
   ```

5. **Regular history cleanup:**
   ```bash
   # Review history periodically
   history | grep -i -E "(token|key|password|secret|bearer)"
   ```

## Disabling This Probe

If shell history scanning takes too long or produces too many findings:

```yaml
# .bagel.yaml
probes:
  shell_history:
    enabled: false
```

Or via command line:
```bash
bagel scan --exclude-probe shell_history
```
