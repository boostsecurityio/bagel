// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIServiceDetector_Name(t *testing.T) {
	detector := NewAIServiceDetector()
	assert.Equal(t, "ai-service", detector.Name())
}

func TestAIServiceDetector_DetectOpenAI(t *testing.T) {
	detector := NewAIServiceDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "OpenAI API key - legacy format",
			content:       `OPENAI_API_KEY="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"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-openai-api-key",
		},
		{
			name:         "No OpenAI key",
			content:      `export API_KEY="some-other-key-12345"`,
			shouldDetect: false,
		},
		{
			name:         "Partial OpenAI key (missing T3BlbkFJ)",
			content:      `sk-abc123456789012345678901234567890123456789`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect OpenAI key")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "OpenAI API Key")
				assert.Equal(t, "ai-service", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any keys")
			}
		})
	}
}

func TestAIServiceDetector_DetectAnthropic(t *testing.T) {
	detector := NewAIServiceDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Anthropic API key",
			content:       `ANTHROPIC_API_KEY="sk-ant-api03-xGmqcir4OAh9bLVKl_1vmYuXP2kjryKlZUlfJ9B25kjNg_enKQQ3qpLu6lkvMHsfxKRyyXrpmQXDCf3eaFTKUZjTfDJkjAA"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-anthropic-api-key",
		},
		{
			name:          "Anthropic Admin API key",
			content:       `export ADMIN_KEY='sk-ant-admin01-xRXaeGx9s9XuRsfR3mmtneR3SAUpu1xh7_DFfyx_J0N7qKhPgO2TIHgCldLGWB0eX3bSsNYxDOtEFngfUsWmXlbo3FeHQAA'`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-anthropic-admin-api-key",
		},
		{
			name:         "Invalid Anthropic key (wrong prefix)",
			content:      `sk-ant-api02-xGmqcir4OAh9bLVKl_1vmYuXP2kjryKlZUlfJ9B25kjNg_enKQQ3qpLu6lkvMHsfxKRyyXrpmQXDCf3eaFTKUZjTfDJkjAA`,
			shouldDetect: false,
		},
		{
			name:         "Invalid Anthropic key (wrong suffix)",
			content:      `sk-ant-api03-xGmqcir4OAh9bLVKl_1vmYuXP2kjryKlZUlfJ9B25kjNg_enKQQ3qpLu6lkvMHsfxKRyyXrpmQXDCf3eaFTKUZjTfDJkjBB`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect Anthropic key")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "Anthropic")
				assert.Equal(t, "ai-service", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any keys")
			}
		})
	}
}

func TestAIServiceDetector_DetectHuggingFace(t *testing.T) {
	detector := NewAIServiceDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
		expectedID    string
	}{
		{
			name:          "Hugging Face access token",
			content:       `HF_TOKEN="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"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-huggingface-access-token",
		},
		{
			name:          "Hugging Face access token (uppercase)",
			content:       `export TOKEN=hf_abcdefghijklmnopqrstuvwxyzabcdefgh `,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-huggingface-access-token",
		},
		{
			name:          "Hugging Face access token (mixed case)",
			content:       `HF_KEY='hf_abcdefghijklmnopqrstuvwxyzabcdefgh'`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-huggingface-access-token",
		},
		{
			name:          "Hugging Face organization token",
			content:       `export ORG_TOKEN="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"`,
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-huggingface-org-token",
		},
		{
			name:          "Hugging Face organization token (mixed case)",
			content:       "api_org_abcdefghijklmnopqrstuvwxyzabcdefgh;",
			shouldDetect:  true,
			expectedCount: 1,
			expectedID:    "ai-service-huggingface-org-token",
		},
		{
			name:         "Invalid Hugging Face token (too short)",
			content:      `hf_abc123`,
			shouldDetect: false,
		},
		{
			name:         "Invalid Hugging Face token (wrong prefix)",
			content:      `hfx_abcdefghijklmnopqrstuvwxyz12345678`,
			shouldDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect Hugging Face token")
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, "critical", findings[0].Severity)
				assert.Contains(t, findings[0].Title, "Hugging Face")
				assert.Equal(t, "ai-service", findings[0].Metadata["detector_name"])
			} else {
				assert.Empty(t, findings, "Should not detect any keys")
			}
		})
	}
}

func TestAIServiceDetector_DetectMultiple(t *testing.T) {
	detector := NewAIServiceDetector()

	content := `
# AI Service Configuration
OPENAI_API_KEY="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"
ANTHROPIC_API_KEY="sk-ant-api03-xGmqcir4OAh9bLVKl_1vmYuXP2kjryKlZUlfJ9B25kjNg_enKQQ3qpLu6lkvMHsfxKRyyXrpmQXDCf3eaFTKUZjTfDJkjAA"
HF_TOKEN="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"
`

	findings := detector.Detect(content, testCtx("config.env"))

	require.Len(t, findings, 3, "Should detect all three AI service keys")

	// Check that we found all three types
	foundTypes := make(map[string]bool)
	for _, finding := range findings {
		foundTypes[finding.ID] = true
		assert.Equal(t, "critical", finding.Severity)
		assert.Equal(t, "ai-service", finding.Metadata["detector_name"])
	}

	assert.True(t, foundTypes["ai-service-openai-api-key"], "Should detect OpenAI key")
	assert.True(t, foundTypes["ai-service-anthropic-api-key"], "Should detect Anthropic key")
	assert.True(t, foundTypes["ai-service-huggingface-access-token"], "Should detect Hugging Face token")
}

func TestAIServiceDetector_WithDelimiters(t *testing.T) {
	detector := NewAIServiceDetector()

	tests := []struct {
		name          string
		content       string
		shouldDetect  bool
		expectedCount int
	}{
		{
			name:          "Key with double quotes",
			content:       `key="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"`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Key with single quotes",
			content:       `key='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'`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Key with backticks",
			content:       "key=`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`",
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Key with semicolon",
			content:       `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;`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Key with newline escape",
			content:       `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\n`,
			shouldDetect:  true,
			expectedCount: 1,
		},
		{
			name:          "Key at end of line",
			content:       "export KEY=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\n",
			shouldDetect:  true,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))

			if tt.shouldDetect {
				require.Len(t, findings, tt.expectedCount, "Expected to detect key with delimiter")
			} else {
				assert.Empty(t, findings, "Should not detect any keys")
			}
		})
	}
}

func TestAIServiceDetector_NoFalsePositives(t *testing.T) {
	detector := NewAIServiceDetector()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Random string",
			content: `some random text without any keys`,
		},
		{
			name:    "Partial key pattern",
			content: `sk-abc123 T3BlbkFJ xyz`,
		},
		{
			name:    "Key-like but wrong format",
			content: `sk-wrong-format-key-that-looks-suspicious`,
		},
		{
			name:    "Documentation reference",
			content: `Use format: sk-proj-[74 chars]T3BlbkFJ[74 chars]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx("test-source"))
			assert.Empty(t, findings, "Should not produce false positives")
		})
	}
}
