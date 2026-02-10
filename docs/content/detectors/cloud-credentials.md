---
title: "Cloud Credentials Detector"
slug: cloud-credentials
url: /detectors/cloud-credentials/
---

The **cloud-credentials** detector identifies cloud provider credentials from AWS, Google Cloud, and Azure.

## Credentials Detected

| Provider | Pattern | Finding ID |
|----------|---------|-----------|
| AWS | Access Key ID | `cloud-credential-aws-access-key-id` |
| Azure | Storage Account Key | `cloud-credential-azure-storage-key` |
| GCP | API Key | `cloud-credential-gcp-api-key` |

All findings have **Critical** severity.

## Pattern Details

### AWS Access Key ID
```
(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}
```

Matches AWS access key IDs with prefixes:
- `AKIA` - Long-term credentials
- `ASIA` - Temporary credentials (STS)
- `A3T[A-Z0-9]` - Older format
- `ABIA`, `ACCA` - Service-specific

### Azure Storage Account Key
```
[A-Za-z0-9+/]{88}==
```

Matches 88-character base64 strings ending with `==` (Azure storage key format).

### GCP API Key
```
AIza[A-Za-z0-9_-]{35}
```

Matches Google Cloud API keys starting with `AIza`.

## Example Findings

### AWS Access Key

```json
{
  "id": "cloud-credential-aws-access-key-id",
  "probe": "cloud",
  "severity": "critical",
  "title": "Cloud Credential Detected (AWS Access Key ID)",
  "message": "A AWS Access Key ID was detected in file:/Users/dev/.aws/credentials.",
  "path": "file:/Users/dev/.aws/credentials"
}
```

### Azure Storage Key

```json
{
  "id": "cloud-credential-azure-storage-key",
  "probe": "env",
  "severity": "critical",
  "title": "Cloud Credential Detected (Azure Storage Account Key)",
  "message": "A Azure Storage Account Key was detected in environment variable AZURE_STORAGE_KEY.",
  "path": "env:AZURE_STORAGE_KEY"
}
```

## Impact of Exposure

### AWS Access Keys
- Full access to AWS services based on IAM permissions
- Potential for cryptocurrency mining, data exfiltration
- Access to S3 buckets, EC2 instances, databases

### Azure Storage Keys
- Full access to storage account
- Read/write/delete blobs and files
- Access to queues and tables

### GCP API Keys
- Access to enabled GCP APIs
- Billing impact from API usage
- Potential data access depending on API

## Remediation

### AWS

1. **Rotate the key immediately:**
   ```bash
   aws iam create-access-key --user-name YOUR_USER
   aws iam delete-access-key --access-key-id AKIAXXXXXXXXXXXXXXXX
   ```

2. **Review CloudTrail** for unauthorized usage

3. **Use IAM roles instead** of long-term credentials:
   - For EC2: Instance profiles
   - For Lambda: Execution roles
   - For CI/CD: OIDC federation

4. **If credentials must be stored:**
   ```bash
   # Use aws-vault
   aws-vault add production
   aws-vault exec production -- aws s3 ls
   ```

### Azure

1. **Regenerate storage keys:**
   ```bash
   az storage account keys renew \
     --account-name mystorageaccount \
     --resource-group myresourcegroup \
     --key key1
   ```

2. **Use managed identities** when running in Azure:
   ```bash
   # Configure managed identity
   az vm identity assign --name myVM --resource-group myRG
   ```

3. **Use SAS tokens** with limited permissions and expiration

### GCP

1. **Delete and recreate the API key:**
   - [Google Cloud Console -> APIs & Services -> Credentials](https://console.cloud.google.com/apis/credentials)
   - Delete the compromised key
   - Create new key with restrictions

2. **Add API key restrictions:**
   - Application restrictions (HTTP referrers, IP addresses)
   - API restrictions (limit which APIs can be called)

3. **Use service accounts instead** where possible

## Best Practices

1. **Prefer short-lived credentials:**
   - AWS: STS, IAM Identity Center
   - Azure: Managed Identities, SAS tokens
   - GCP: Workload Identity, Service Account impersonation

2. **Never commit credentials:**
   ```gitignore
   .aws/
   .azure/
   .config/gcloud/
   *.json  # Service account keys
   ```

3. **Use environment-based configuration:**
   ```bash
   # AWS
   export AWS_PROFILE=production

   # Azure
   az login

   # GCP
   gcloud auth application-default login
   ```

4. **Set up credential rotation:**
   - AWS: Use IAM Access Analyzer for unused credentials
   - Azure: Set key expiration policies
   - GCP: Monitor key age and rotate regularly

5. **Enable cloud provider secret scanning:**
   - AWS: Enable AWS Secrets Manager
   - Azure: Enable Defender for Cloud
   - GCP: Enable Secret Manager with audit logging

## Related

- [Cloud Probe]({{< relref "/probes/cloud" >}}) - Scans cloud credential files
