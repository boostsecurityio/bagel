---
title: "AI Service Detector"
slug: ai-service
url: /detectors/ai-service/
---

The **ai-service** detector identifies API keys for AI and machine learning services.

## Services Detected

| Service | Finding ID | Pattern Prefix |
|---------|-----------|----------------|
| OpenAI | `ai-service-openai-api-key` | `sk-proj-`, `sk-svcacct-`, `sk-` |
| Anthropic | `ai-service-anthropic-api-key` | `sk-ant-api03-` |
| Anthropic Admin | `ai-service-anthropic-admin-api-key` | `sk-ant-admin01-` |
| HuggingFace | `ai-service-huggingface-access-token` | `hf_` |
| HuggingFace Org | `ai-service-huggingface-org-token` | `api_org_` |

All findings have **Critical** severity.

## Pattern Details

### OpenAI API Key
```
sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]+T3BlbkFJ[A-Za-z0-9_-]+
sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}
```

OpenAI keys contain a base64-encoded marker `T3BlbkFJ` (decodes to "OpenAI").

### Anthropic API Key
```
sk-ant-api03-[a-zA-Z0-9_-]{93}AA
```

Standard Anthropic API keys for Claude access.

### Anthropic Admin API Key
```
sk-ant-admin01-[a-zA-Z0-9_-]{93}AA
```

Administrative keys with elevated permissions.

### HuggingFace Access Token
```
hf_[a-z]{34}
```

User access tokens for HuggingFace Hub.

### HuggingFace Organization Token
```
api_org_[a-z]{34}
```

Organization-level API tokens.

## Example Finding

```json
{
  "id": "ai-service-openai-api-key",
  "fingerprint": "...",
  "probe": "env",
  "severity": "critical",
  "title": "AI Service API Key Detected (OpenAI API Key)",
  "message": "An OpenAI API Key was detected in environment variable OPENAI_API_KEY. This credential provides access to AI services and may incur costs...",
  "path": "env:OPENAI_API_KEY",
  "metadata": {
    "detector_name": "ai-service",
    "token_type": "openai-api-key"
  }
}
```

## Impact of Exposure

### Financial
- **OpenAI**: GPT-4 usage can cost $0.01-$0.06 per 1K tokens
- **Anthropic**: Claude usage has similar per-token costs
- Attackers can run up significant bills quickly

### Data Exposure
- API calls may expose your prompts and data
- Fine-tuned models could be accessed
- Training data might be extractable

### Reputational
- Attackers could generate harmful content under your account
- Automated abuse could lead to account suspension

## Remediation

### OpenAI

1. **Revoke the key immediately:**
   - Go to [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
   - Delete the compromised key

2. **Check usage:**
   - Review [usage dashboard](https://platform.openai.com/usage)
   - Look for unexpected API calls

3. **Create a new key with restrictions:**
   - Set usage limits
   - Use project-specific keys

### Anthropic

1. **Revoke the key:**
   - Go to [console.anthropic.com](https://console.anthropic.com)
   - Navigate to API keys section
   - Delete the compromised key

2. **Review account activity** for unauthorized usage

### HuggingFace

1. **Revoke the token:**
   - Go to [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
   - Delete the compromised token

2. **Review repository access** and activity

## Best Practices

1. **Use environment variables:**
   ```bash
   # Don't hardcode
   export OPENAI_API_KEY=$(op read "op://Private/OpenAI/api-key")
   ```

2. **Set usage limits:**
   - OpenAI: Set spending limits in billing settings
   - Anthropic: Configure rate limits
   - HuggingFace: Use read-only tokens when possible

3. **Use project-specific keys:**
   - Create separate keys for each project
   - Easier to rotate and audit

4. **Secure your prompts too:**
   - API keys in shell history often accompany prompts
   - Prompts may contain sensitive data

5. **Use server-side proxies:**
   - Don't expose AI keys in client-side code
   - Route requests through your backend

6. **Monitor for abuse:**
   - Set up billing alerts
   - Review usage regularly
   - Use API logs to detect anomalies

## Common Exposure Vectors

| Vector | Example |
|--------|---------|
| Shell history | `curl -H "Authorization: Bearer sk-..."` |
| .env files | `OPENAI_API_KEY=sk-...` |
| Jupyter notebooks | API key in code cells |
| Git commits | Hardcoded in source |
| IDE configs | JetBrains run configurations |

## Related

- [Environment Probe]({{< relref "/probes/env" >}}) - Checks environment variables
- [Shell History Probe]({{< relref "/probes/shell-history" >}}) - Checks command history
