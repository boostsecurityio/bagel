---
title: "AI CLI Probe"
slug: ai-cli
url: /probes/ai-cli/
---

The **ai_cli** probe scans credential files and chat logs for AI CLI tools (Gemini, Codex, Claude, OpenCode) to detect exposed secrets.

## What It Checks

The probe examines two categories of files:

### Credential Files

Authentication and OAuth files stored by AI CLI tools.

| Tool | File Pattern |
|------|-------------|
| Gemini | `~/.gemini/oauth_creds.json` |
| Codex | `~/.codex/auth.json` |
| OpenCode | `~/.local/share/opencode/auth.json` |

### Chat Log Files

Session transcripts and conversation logs that may contain pasted secrets.

| Tool | File Pattern |
|------|-------------|
| Gemini | `~/.gemini/tmp/*/chats/*.json` |
| Codex | `~/.codex/sessions/*/*/*/rollout-*.jsonl` |
| Claude | `~/.claude/projects/*/*.jsonl` |
| OpenCode | `~/.local/share/opencode/storage/part/msg_*/prt_*.json` |

## Why This Matters

AI CLI tools store authentication credentials locally and maintain chat logs that developers interact with daily. These files can contain:

- **OAuth tokens and API keys** used to authenticate with AI services
- **Secrets pasted into prompts** (API keys, passwords, connection strings)
- **Code snippets with embedded credentials** shared during debugging sessions
- **Cloud provider keys** included in infrastructure discussions

Because developers routinely paste sensitive material into AI chat sessions, the chat logs become an overlooked vector for secret exposure.

## Finding Types

The probe delegates detection to all registered secret detectors. Common findings include:

| Finding ID | Severity | Description |
|-----------|----------|-------------|
| `ai-service-openai-api-key` | Critical | OpenAI API key detected |
| `ai-service-anthropic-api-key` | Critical | Anthropic API key detected |
| `ai-service-anthropic-admin-api-key` | Critical | Anthropic admin API key detected |
| `ai-service-huggingface-access-token` | Critical | HuggingFace access token detected |
| `github-token-*` | Critical | GitHub personal access token detected |
| `cloud-credential-*` | Critical | Cloud provider credential detected (e.g., `cloud-credential-aws-access-key-id`) |
| `jwt-jwt-token` | Critical | JWT (JWS) token detected |
| `jwt-jwe-token` | Critical | Encrypted JWT (JWE) token detected |

Any detector in the registry can produce findings from AI CLI files.

## Example Finding

```json
{
  "id": "ai-service-openai-api-key",
  "fingerprint": "sha256:...",
  "probe": "ai_cli",
  "severity": "critical",
  "title": "AI Service API Key Detected (OpenAI API Key)",
  "message": "An OpenAI API Key was detected in file:/Users/dev/.codex/auth.json.",
  "path": "file:/Users/dev/.codex/auth.json",
  "metadata": {
    "detector_name": "ai-service",
    "token_type": "openai-api-key"
  }
}
```

## Remediation

### 1. Clean Up Chat Logs

Remove chat logs that contain sensitive material:

```bash
# Gemini
rm -rf ~/.gemini/tmp/*/chats/

# Codex
rm -rf ~/.codex/sessions/

# Claude
rm -rf ~/.claude/projects/

# OpenCode
rm -rf ~/.local/share/opencode/storage/
```

### 2. Avoid Pasting Secrets into AI Prompts

- Use file references or environment variable names instead of actual values
- Use `.env` files with a secret manager rather than hardcoding values

## Best Practices

1. **Treat chat logs as sensitive:** AI conversation history may accumulate secrets over time without you realizing it.

2. **Periodically clear session data:** Set up a cron job or alias to prune old chat logs.

3. **Use scoped credentials for AI tools:** Create dedicated API keys with minimal permissions for AI CLI authentication.

4. **Review before committing:** Ensure `.gemini/`, `.codex/`, `.claude/`, and `.local/share/opencode/` are in your global `.gitignore`:
   ```gitignore
   .gemini/
   .codex/
   .claude/
   .local/share/opencode/
   ```

## Related

- [AI Service Detector]({{< relref "/detectors/ai-service" >}}) - Detects AI service API keys
- [Environment Probe]({{< relref "/probes/env" >}}) - Checks environment variables for secrets
- [Shell History Probe]({{< relref "/probes/shell-history" >}}) - Checks command history for secrets
