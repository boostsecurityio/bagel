// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericAPIKeyDetector_Name(t *testing.T) {
	detector := NewGenericAPIKeyDetector()
	assert.Equal(t, "generic-api-key", detector.Name())
}

func TestGenericAPIKeyDetector_CalculateEntropy(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name          string
		input         string
		minEntropy    float64
		maxEntropy    float64
		shouldBeAbove float64
		shouldBeBelow float64
	}{
		{
			name:       "Empty string",
			input:      "",
			minEntropy: 0.0,
			maxEntropy: 0.0,
		},
		{
			name:       "Single character repeated",
			input:      "aaaaaaaaaaaaaa",
			minEntropy: 0.0,
			maxEntropy: 0.0,
		},
		{
			name:          "Low entropy placeholder",
			input:         "your_api_key_here",
			shouldBeBelow: 3.5,
		},
		{
			name:          "High entropy random string",
			input:         "9dj2K8sL4mP7nQ3rT6vW1xY5zA",
			shouldBeAbove: 3.5,
		},
		{
			name:          "Real API key pattern",
			input:         "sk_live_51HqT2fK3nP7sL9mX4wY8vR2jD6bN",
			shouldBeAbove: 3.5,
		},
		{
			name:          "Sequential characters",
			input:         "abcdefghijklmnop",
			shouldBeBelow: 4.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := detector.calculateEntropy(tt.input)

			if tt.minEntropy != 0 || tt.maxEntropy != 0 {
				assert.GreaterOrEqual(t, entropy, tt.minEntropy)
				assert.LessOrEqual(t, entropy, tt.maxEntropy)
			}

			if tt.shouldBeAbove > 0 {
				assert.Greater(t, entropy, tt.shouldBeAbove, "Entropy should be above threshold")
			}

			if tt.shouldBeBelow > 0 {
				assert.Less(t, entropy, tt.shouldBeBelow, "Entropy should be below threshold")
			}
		})
	}
}

func TestGenericAPIKeyDetector_ShouldExclude(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name          string
		value         string
		shouldExclude bool
	}{
		// Placeholders
		{
			name:          "YOUR_API_KEY placeholder",
			value:         "your_api_key",
			shouldExclude: true,
		},
		{
			name:          "MY_TOKEN placeholder",
			value:         "my_token",
			shouldExclude: true,
		},
		{
			name:          "EXAMPLE_SECRET placeholder",
			value:         "example_secret",
			shouldExclude: true,
		},
		{
			name:          "TEST_PASSWORD placeholder",
			value:         "test_password",
			shouldExclude: true,
		},
		{
			name:          "DEMO_KEY placeholder",
			value:         "demo-key",
			shouldExclude: true,
		},
		// Common patterns
		{
			name:          "XXX pattern",
			value:         "xxxxxxxxxx",
			shouldExclude: true,
		},
		{
			name:          "Asterisks",
			value:         "**********",
			shouldExclude: true,
		},
		{
			name:          "Dots placeholder",
			value:         "...........",
			shouldExclude: true,
		},
		{
			name:          "ABC123 pattern",
			value:         "abc123xyz",
			shouldExclude: true,
		},
		// Environment variable references
		{
			name:          "Simple env var",
			value:         "$API_KEY",
			shouldExclude: true,
		},
		{
			name:          "Env var with braces",
			value:         "${SECRET_TOKEN}",
			shouldExclude: true,
		},
		// Common non-secrets
		{
			name:          "Boolean true",
			value:         "true",
			shouldExclude: true,
		},
		{
			name:          "Boolean false",
			value:         "false",
			shouldExclude: true,
		},
		{
			name:          "Null value",
			value:         "null",
			shouldExclude: true,
		},
		{
			name:          "Localhost",
			value:         "localhost",
			shouldExclude: true,
		},
		{
			name:          "127.0.0.1",
			value:         "127.0.0.1",
			shouldExclude: true,
		},
		// Too short
		{
			name:          "Short value",
			value:         "abc123",
			shouldExclude: true,
		},
		// Valid secrets (should NOT exclude)
		{
			name:          "Real API key",
			value:         "sk_live_51HqT2fK3nP7sL9mX4wY8vR2jD6bN",
			shouldExclude: false,
		},
		{
			name:          "Random secret",
			value:         "9dj2K8sL4mP7nQ3rT6vW1xY5zA",
			shouldExclude: false,
		},
		{
			name:          "GitHub token",
			value:         "ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
			shouldExclude: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.shouldExclude(tt.value)
			assert.Equal(t, tt.shouldExclude, result)
		})
	}
}

func TestGenericAPIKeyDetector_Detect(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
	}{
		// Real API key patterns
		{
			name:          "Stripe API key",
			content:       `STRIPE_SECRET_KEY=sk_live_51HqT2fK3nP7sL9mX4wY8vR2jD6bNcG5hW3zY`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "GitHub token",
			content:       `github_token = ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "API key in JSON",
			content:       `{"api_key": "9dj2K8sL4mP7nQ3rT6vW1xY5zA", "name": "test"}`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Secret in YAML",
			content:       `secret: r3aL5ecr3tK3yW1thH1ghEntr0py`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Auth token in code",
			content:       `const authToken = "8xK2mP9vL3nQ7rT4wY1zN6bH5cG";`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Password in config",
			content:       `password=xY9mK2pL7nQ4rT8wZ3vB6hN1cF`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Access key in env file",
			content:       `ACCESS_KEY="mN5pQ8rT2wY6zA9cF3hK7vL1xB4"`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		// Multiple secrets
		{
			name: "Multiple API keys",
			content: `
api_key_1 = "9dj2K8sL4mP7nQ3rT6vW1xY5zA"
api_key_2 = "3mL5nP8qR2tV7wY1zB4cF6hJ9k"
`,
			shouldDetect:  true,
			expectedCount: 2,
		},
		// Should NOT detect (placeholders)
		{
			name:         "Placeholder YOUR_API_KEY",
			content:      `api_key = your_api_key`,
			shouldDetect: false,
		},
		{
			name:         "Placeholder EXAMPLE",
			content:      `secret = example_secret_here`,
			shouldDetect: false,
		},
		{
			name:         "Environment variable reference",
			content:      `token = $TOKEN`,
			shouldDetect: false,
		},
		{
			name:         "Environment variable with braces",
			content:      `api_key = ${API_KEY}`,
			shouldDetect: false,
		},
		// Should NOT detect (low entropy)
		{
			name:         "Low entropy value",
			content:      `password = aaaaaaaaaaaaaa`,
			shouldDetect: false,
		},
		{
			name:         "Sequential characters",
			content:      `secret = abcdefghijklmnop`,
			shouldDetect: false,
		},
		{
			name:         "Common non-secret",
			content:      `enabled = true`,
			shouldDetect: false,
		},
		// Should NOT detect (too short)
		{
			name:         "Too short value",
			content:      `key = abc123`,
			shouldDetect: false,
		},
		// Edge cases
		{
			name:         "No key-value pair",
			content:      `This is just some text without any secrets`,
			shouldDetect: false,
		},
		{
			name:         "URL without secret",
			content:      `https://example.com/api/endpoint`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect API key(s)")
				assert.Equal(t, "generic-api-key", findings[0].ID)
				assert.Equal(t, "high", findings[0].Severity)
				assert.Equal(t, "generic-api-key", findings[0].Metadata["detector_name"])
				assert.Contains(t, findings[0].Metadata, "entropy")
			} else {
				assert.Empty(t, findings, "Should not detect any secrets")
			}
		})
	}
}

func TestGenericAPIKeyDetector_RealWorldExamples(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
	}{
		{
			name: "Environment file with secrets",
			content: `
# Application Configuration
APP_NAME=myapp
DEBUG=false
STRIPE_API_KEY=sk_live_51HqT2fK3nP7sL9mX4wY8vR2jD6bNcG5hW3zY
DATABASE_URL=postgres://user:pass@localhost/db
JWT_SECRET=9dj2K8sL4mP7nQ3rT6vW1xY5zA
`,
			shouldDetect:  true,
			expectedCount: 2, // Stripe key and JWT secret
		},
		{
			name: "Python code with API key",
			content: `
import requests

API_KEY = "xY9mK2pL7nQ4rT8wZ3vB6hN1cF5gJ2"
headers = {"Authorization": f"Bearer {API_KEY}"}
`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name: "JavaScript config with token",
			content: `
module.exports = {
  apiKey: "3mL5nP8qR2tV7wY1zB4cF6hJ9kM2",
  endpoint: "https://api.example.com"
};
`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name: "Docker Compose with credentials",
			content: `
version: '3'
services:
  app:
    environment:
      - API_SECRET=r3aL5ecr3tK3yW1thH1ghEntr0py
      - DEBUG=true
`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name: "Terraform with sensitive data",
			content: `
variable "api_key" {
  api_key = "8xK2mP9vL3nQ7rT4wY1zN6bH5cG9jF2"
  sensitive = true
}
`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name: "Config file with placeholders (no detection)",
			content: `
# Configuration template
API_KEY=your_api_key_here
SECRET_TOKEN=replace_with_your_token
PASSWORD=change_me
`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				assert.GreaterOrEqual(t, len(findings), tt.expectedCount, "Expected to detect secrets")
				for _, finding := range findings {
					assert.NotEmpty(t, finding.Message)
					assert.NotEmpty(t, finding.Title)
					assert.Equal(t, "high", finding.Severity)
					assert.Contains(t, finding.Message, "entropy")
				}
			} else {
				assert.Empty(t, findings, "Should not detect placeholders")
			}
		})
	}
}

func TestGenericAPIKeyDetector_EntropyThreshold(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name          string
		content       string
		expectEntropy float64
		shouldDetect  bool
	}{
		{
			name:         "Above threshold",
			content:      `secret = "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
		{
			name:         "Below threshold - repeated chars",
			content:      `secret = "aaaaaaaaaaaa"`,
			shouldDetect: false,
		},
		{
			name:         "Below threshold - sequential",
			content:      `secret = "abcdefghijklmno"`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.NotEmpty(t, findings, "Should detect high entropy secret")
				entropy := findings[0].Metadata["entropy"].(string)
				assert.NotEmpty(t, entropy, "Should include entropy in metadata")
			} else {
				assert.Empty(t, findings, "Should not detect low entropy value")
			}
		})
	}
}

func TestGenericAPIKeyDetector_VariousAssignmentOperators(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	tests := []struct {
		name         string
		content      string
		shouldDetect bool
	}{
		{
			name:         "Equals sign",
			content:      `api_key = "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
		{
			name:         "Colon",
			content:      `api_key: "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
		{
			name:         "Arrow",
			content:      `api_key => "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
		{
			name:         "Greater than",
			content:      `api_key > "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
		{
			name:         "Comma separated",
			content:      `api_key, "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`,
			shouldDetect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))
			if tt.shouldDetect {
				assert.GreaterOrEqual(t, len(findings), 1, "Should detect with various operators")
			} else {
				assert.Empty(t, findings, "Should not detect")
			}
		})
	}
}

func TestGenericAPIKeyDetector_FindingMetadata(t *testing.T) {
	detector := NewGenericAPIKeyDetector()

	content := `api_key = "9dj2K8sL4mP7nQ3rT6vW1xY5zA"`
	findings := detector.Detect(content, testCtx("test-config.yaml"))

	require.Len(t, findings, 1, "Should detect exactly one finding")

	finding := findings[0]
	assert.Equal(t, "generic-api-key", finding.ID)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "Generic API Key Detected", finding.Title)
	assert.Contains(t, finding.Message, "entropy")
	assert.Contains(t, finding.Message, "test-config.yaml")
	assert.Equal(t, "test-config.yaml", finding.Path)

	// Check metadata
	assert.Equal(t, "generic-api-key", finding.Metadata["detector_name"])
	assert.Equal(t, "generic-api-key", finding.Metadata["token_type"])
	assert.Equal(t, "Generic API Key or High-Entropy Secret", finding.Metadata["description"])
	assert.NotEmpty(t, finding.Metadata["entropy"])
}
