---
title: "Cloud Probe"
slug: cloud
url: /probes/cloud/
---

The **cloud** probe scans cloud provider configuration and credential files for exposed secrets.

## What It Checks

The probe examines cloud configuration files and uses the [Cloud Credentials Detector]({{< relref "/detectors/cloud-credentials" >}}) to find exposed credentials:

| Provider | Files Scanned |
|----------|---------------|
| AWS | `~/.aws/config`, `~/.aws/credentials` |
| GCP | `~/.config/gcloud/*` |
| Azure | `~/.azure/*` |

## Finding Types

Secrets found by this probe will be tagged with the Cloud Credentials Detector findings:

| Finding ID | Description |
|-----------|-------------|
| `cloud-credential-aws-access-key-id` | AWS Access Key ID |
| `cloud-credential-azure-storage-key` | Azure Storage Account Key |
| `cloud-credential-gcp-api-key` | Google Cloud API Key |

All findings have **Critical** severity.

## Best Practices
Prefer using Short Lived credentials instead of long-lived static credentials. Use IAM roles, Workload Identity Federation, or Managed Identities to provide temporary access to cloud resources.

Short lived credentials should use as short as possible session durations and ideally require a second factor to refresh.

