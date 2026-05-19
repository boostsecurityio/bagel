// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/boostsecurityio/bagel/pkg/detector"
	"github.com/boostsecurityio/bagel/pkg/fileindex"
	"github.com/boostsecurityio/bagel/pkg/models"
	"github.com/rs/zerolog/log"
)

// CloudProbe scans cloud provider, SaaS CLI, and code-forge auth
// files for embedded credentials.
type CloudProbe struct {
	enabled          bool
	config           models.ProbeSettings
	detectorRegistry *detector.Registry
	fileIndex        *fileindex.FileIndex
}

// NewCloudProbe creates a new cloud credentials probe
func NewCloudProbe(config models.ProbeSettings, registry *detector.Registry) *CloudProbe {
	return &CloudProbe{
		enabled:          config.Enabled,
		config:           config,
		detectorRegistry: registry,
	}
}

// Name returns the probe name
func (p *CloudProbe) Name() string {
	return "cloud"
}

// IsEnabled returns whether the probe is enabled
func (p *CloudProbe) IsEnabled() bool {
	return p.enabled
}

// SetFingerprintSalt sets the fingerprint salt on the detector registry (implements FingerprintSaltAware)
func (p *CloudProbe) SetFingerprintSalt(salt string) {
	p.detectorRegistry.SetFingerprintSalt(salt)
}

// SetFileIndex sets the file index for this probe (implements FileIndexAware)
func (p *CloudProbe) SetFileIndex(index *fileindex.FileIndex) {
	p.fileIndex = index
}

// cloudCredentialPatterns lists every file-index pattern whose matches
// hold cloud-provider or SaaS-CLI credentials.
var cloudCredentialPatterns = []string{
	// AWS
	"aws_config",
	"aws_credentials",
	"aws_sso_cache",
	"aws_cli_cache",

	// Azure
	"azure_config",
	"azure_tokens",

	// GCP
	"gcp_config",
	"gcp_credentials",

	// HashiCorp Vault
	"vault_token",

	// Single-vendor cloud / SaaS CLIs (Phase D-1).
	"oci_config",
	"aliyun_config",
	"bluemix_config",
	"doctl_config",
	"hcloud_config",
	"scw_config",
	"linode_config",
	"fly_config",
	"vercel_config",
	"railway_config",
	"snowflake_config",
	"doppler_config",
	"gh_hosts",
	"glab_config",
	"hub_config",
	"netrc_file",
}

// Execute runs the cloud probe
func (p *CloudProbe) Execute(ctx context.Context) ([]models.Finding, error) {
	var findings []models.Finding

	// If file index is not available, skip probe
	if p.fileIndex == nil {
		log.Ctx(ctx).Warn().
			Str("probe", p.Name()).
			Msg("File index not available, skipping cloud probe")
		return findings, nil
	}

	seen := make(map[string]struct{})
	for _, pattern := range cloudCredentialPatterns {
		for _, filePath := range p.fileIndex.Get(pattern) {
			if _, dup := seen[filePath]; dup {
				continue
			}
			seen[filePath] = struct{}{}
			// AWS SSO + CLI caches are rewritten on each `aws sso
			// login` / `aws sts assume-role` and old files linger on
			// disk indefinitely. Skip when the embedded expiry has
			// passed so we don't surface dead credentials as findings.
			if isAWSCachePattern(pattern) && awsCacheExpired(filePath) {
				log.Ctx(ctx).Debug().
					Str("file", filePath).
					Str("pattern", pattern).
					Msg("Skipping expired AWS credential cache")
				continue
			}
			findings = append(findings, p.processCloudFile(ctx, filePath)...)
		}
	}

	log.Ctx(ctx).Debug().
		Int("cloud_files_scanned", len(seen)).
		Msg("Cloud probe completed")

	// Check for Kubernetes service account token (system path, outside home dir)
	findings = append(findings, p.checkK8sServiceAccountToken(ctx)...)

	return findings, nil
}

const k8sServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// checkK8sServiceAccountToken checks for the presence of a Kubernetes service account token
func (p *CloudProbe) checkK8sServiceAccountToken(ctx context.Context) []models.Finding {
	if _, err := os.Stat(k8sServiceAccountTokenPath); err != nil {
		return nil
	}

	log.Ctx(ctx).Debug().
		Str("path", k8sServiceAccountTokenPath).
		Msg("Found Kubernetes service account token")

	return []models.Finding{
		{
			ID:          "k8s-service-account-token",
			Type:        models.FindingTypeSecret,
			Fingerprint: models.FingerprintFromFields("k8s-service-account-token", k8sServiceAccountTokenPath),
			Probe:       p.Name(),
			Severity:    "high",
			Title:       "Kubernetes Service Account Token Found",
			Description: "A Kubernetes service account token is mounted at the default path. " +
				"Verify this token has minimal RBAC permissions and consider disabling automountServiceAccountToken if not needed.",
			Message: "Kubernetes service account token found at " + k8sServiceAccountTokenPath,
			Path:    "file:" + k8sServiceAccountTokenPath,
			Metadata: map[string]interface{}{
				"token_path": k8sServiceAccountTokenPath,
			},
		},
	}
}

// processCloudFile reads and analyzes a cloud credential file. Cloud
// credentials are either INI (.aws/credentials) or JSON service-account files
// with private_key kept on a single line via \n escapes — per-line scanning
// works for both and lets findings carry a line number.
func (p *CloudProbe) processCloudFile(ctx context.Context, filePath string) []models.Finding {
	return scanFileLines(ctx, filePath, p.Name(), p.detectorRegistry, 0)
}

// isAWSCachePattern returns true for the two AWS file-index patterns
// whose contents are credential caches with an embedded expiry.
func isAWSCachePattern(pattern string) bool {
	return pattern == "aws_sso_cache" || pattern == "aws_cli_cache"
}

// awsCacheExpiryGrace covers clock skew between the local machine and
// AWS at the moment the cache was written. Keeping the grace small
// avoids re-reporting almost-expired tokens; one minute is enough to
// absorb realistic skew without making us report dead tokens for long.
const awsCacheExpiryGrace = time.Minute

// awsCacheExpired returns true when the AWS SSO or CLI cache file at
// path has already passed its embedded expiry. The CLI cache wraps
// credentials in `{"Credentials":{"Expiration":"<rfc3339>"}}` (sts
// assume-role / get-credentials shape); the SSO cache uses a
// top-level `expiresAt`. Either field signals when the cached token
// stops authenticating.
//
// We err toward reporting on any parse / read / time-format error:
// when we can't tell whether the cache is dead, we still surface it.
// This keeps the false-negative rate low while killing the dominant
// false-positive source (long-stale caches sitting on disk).
func awsCacheExpired(path string) bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc struct {
		// AWS CLI cache (sts assume-role output / GetSessionToken).
		Credentials *struct {
			Expiration string `json:"Expiration"`
		} `json:"Credentials"`
		// AWS SSO cache.
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return false
	}
	expiryStr := ""
	switch {
	case doc.Credentials != nil && doc.Credentials.Expiration != "":
		expiryStr = doc.Credentials.Expiration
	case doc.ExpiresAt != "":
		expiryStr = doc.ExpiresAt
	default:
		return false
	}
	t, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		return false
	}
	return time.Now().UTC().After(t.Add(awsCacheExpiryGrace))
}
