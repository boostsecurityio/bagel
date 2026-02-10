// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudCredentialsDetector_Name(t *testing.T) {
	detector := NewCloudCredentialsDetector()
	assert.Equal(t, "cloud-credentials", detector.Name())
}

func TestCloudCredentialsDetector_AWS(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "AWS Access Key ID (AKIA prefix)",
			content:       `AKIAIOSFODNNEXAMPLE2`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-aws-access-key-id",
		},
		{
			name:          "AWS Access Key ID with assignment",
			content:       `aws_access_key_id=AKIAIEXAMPLEKEY2TEST`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-aws-access-key-id",
		},
		{
			name:          "AWS Access Key ID (ASIA prefix - temporary credentials)",
			content:       `export AWS_ACCESS_KEY_ID="ASIAJEXAMPLEEXAMPLE2"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-aws-access-key-id",
		},
		{
			name: "AWS credentials file",
			content: `[default]
aws_access_key_id = AKIAIOSFODNNEXAMPLE2
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-aws-access-key-id",
		},
		{
			name:         "Invalid AWS Access Key ID (wrong prefix)",
			content:      `AWS_ACCESS_KEY_ID=XKIAIOSFODNNEXAMPLE2`,
			shouldDetect: false,
		},
		{
			name:         "Invalid AWS Access Key ID (too short)",
			content:      `aws_access_key_id=AKIASHORT`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect AWS credentials")
				if tt.expectedID != "" {
					assert.Equal(t, tt.expectedID, findings[0].ID)
				}
				assert.Equal(t, "cloud-credentials", findings[0].Metadata["detector_name"])
				// All cloud credentials are now critical severity
				assert.Equal(t, "critical", findings[0].Severity)
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestCloudCredentialsDetector_GCP(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "GCP API Key",
			content:       `GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-gcp-api-key",
		},
		{
			name:          "GCP API Key in code",
			content:       `const apiKey = "AIzaSyC7p4WQZX8kN9H2fGt5Lm6KjPqRsTuVwXy";`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-gcp-api-key",
		},
		{
			name:         "Invalid GCP API Key (wrong prefix)",
			content:      `AIZA1234567890123456789012345678901234`,
			shouldDetect: false,
		},
		{
			name:         "Invalid GCP API Key (too short)",
			content:      `AIzaSyShortKey`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect GCP credentials")
				if tt.expectedID != "" {
					assert.Equal(t, tt.expectedID, findings[0].ID)
				}
				assert.Equal(t, "cloud-credentials", findings[0].Metadata["detector_name"])
				// All cloud credentials are now critical severity
				assert.Equal(t, "critical", findings[0].Severity)
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestCloudCredentialsDetector_Azure(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Azure Storage Account Key (standalone)",
			content:       `abcDEF123+/xyz789ABCDEF456+/ghiJKL012+/mnoPQR345+/stuVWX678+/yzaBC901+/defGHI234+/jklMN0==`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-azure-storage-key",
		},
		{
			name:          "Azure Storage Account Key with assignment",
			content:       `account_key=abcDEF123+/xyz789ABCDEF456+/ghiJKL012+/mnoPQR345+/stuVWX678+/yzaBC901+/defGHI234+/jklMN0==`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "cloud-credential-azure-storage-key",
		},
		{
			name:         "Invalid Azure Storage Key (wrong length)",
			content:      `abcDEF123+/xyz789ABCDEF456==`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect Azure credentials")
				if tt.expectedID != "" {
					assert.Equal(t, tt.expectedID, findings[0].ID)
				}
				assert.Equal(t, "cloud-credentials", findings[0].Metadata["detector_name"])
				// All cloud credentials are now critical severity
				assert.Equal(t, "critical", findings[0].Severity)
			} else {
				assert.Empty(t, findings, "Should not detect any credentials")
			}
		})
	}
}

func TestCloudCredentialsDetector_MultipleProviders(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	content := `
# Multi-cloud configuration
[aws]
aws_access_key_id = AKIAIOSFODNNEXAMPLE2

[gcp]
api_key = AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe

[azure]
account_key=abcDEF123+/xyz789ABCDEF456+/ghiJKL012+/mnoPQR345+/stuVWX678+/yzaBC901+/defGHI234+/jklMN0==
`

	findings := detector.Detect(content, testCtx("cloud-config.txt"))

	require.GreaterOrEqual(t, len(findings), 3, "Should detect credentials from all providers")

	// Count findings by provider
	awsCount := 0
	gcpCount := 0
	azureCount := 0

	for _, finding := range findings {
		assert.Equal(t, "cloud-credentials", finding.Metadata["detector_name"])
		assert.Equal(t, "critical", finding.Severity)
		tokenType := finding.Metadata["token_type"].(string)

		if len(tokenType) >= 3 && tokenType[:3] == "aws" {
			awsCount++
		} else if len(tokenType) >= 3 && tokenType[:3] == "gcp" {
			gcpCount++
		} else if len(tokenType) >= 5 && tokenType[:5] == "azure" {
			azureCount++
		}
	}

	assert.GreaterOrEqual(t, awsCount, 1, "Should detect AWS Access Key ID")
	assert.GreaterOrEqual(t, gcpCount, 1, "Should detect GCP API key")
	assert.GreaterOrEqual(t, azureCount, 1, "Should detect Azure storage key")
}

func TestCloudCredentialsDetector_NoFalsePositives(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Documentation placeholder",
			content: `aws_access_key_id=YOUR_ACCESS_KEY_HERE`,
		},
		{
			name:    "Code comment",
			content: `# Set your AWS_ACCESS_KEY_ID in the environment`,
		},
		{
			name:    "Example format",
			content: `AKIA followed by 16 characters`,
		},
		{
			name:    "Short random string",
			content: `key=abc123def456`,
		},
		{
			name:    "Invalid base64 length",
			content: `secret=abcDEF123xyz789==`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))
			assert.Empty(t, findings, "Should not produce false positives")
		})
	}
}

func TestCloudCredentialsDetector_RealWorldExamples(t *testing.T) {
	detector := NewCloudCredentialsDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
	}{
		{
			name: "AWS credentials file",
			content: `[default]
aws_access_key_id = AKIAIEXAMPLEKEY2TEST
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name: "Docker environment file",
			content: `AWS_ACCESS_KEY_ID=AKIAIEXAMPLEKEY2TEST
GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe`,
			shouldDetect:  true,
			expectedCount: 2,
		},
		{
			name:          "Azure connection string",
			content:       `DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abcDEF123+/xyz789ABCDEF456+/ghiJKL012+/mnoPQR345+/stuVWX678+/yzaBC901+/defGHI234+/jklMN0==;EndpointSuffix=core.windows.net`,
			shouldDetect:  true,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				assert.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect credentials")
				for _, finding := range findings {
					assert.NotEmpty(t, finding.Message)
					assert.NotEmpty(t, finding.Title)
					assert.Equal(t, "critical", finding.Severity)
				}
			} else {
				assert.Empty(t, findings, "Should not detect credentials")
			}
		})
	}
}
