// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHPrivateKeyDetector_Detect(t *testing.T) {
	detector := NewSSHPrivateKeyDetector()

	tests := []struct {
		name          string
		content       string
		source        string
		wantCount     int
		wantEncrypted bool
		wantKeyType   string
		wantSeverity  string
	}{
		{
			name: "unencrypted RSA key",
			content: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_rsa",
			wantCount:     1,
			wantEncrypted: false,
			wantKeyType:   "RSA",
			wantSeverity:  "critical",
		},
		{
			name: "encrypted RSA key",
			content: `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,1234567890ABCDEF

MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_rsa",
			wantCount:     1,
			wantEncrypted: true,
			wantKeyType:   "RSA",
			wantSeverity:  "low",
		},
		{
			name: "unencrypted OPENSSH key",
			content: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtPwPYNrPFZXfMJKLPvKnLvG8BvPvvBvKnLvPFZXfMJKLPvPvBvKn
LvG8BvPvvBvKnLvPFZXfMJKLPvKnLvG8BvPvvBvKnLvPFZXfMJKLPvKnLv==
-----END OPENSSH PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_ed25519",
			wantCount:     1,
			wantEncrypted: false,
			wantKeyType:   "OPENSSH",
			wantSeverity:  "critical",
		},
		{
			name: "encrypted OPENSSH key",
			content: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDl8IT7hX
EGIr0mYAIkOtbUAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQC0/A9g2s8V
ld8wkos+8qcu8bwG8++8G8qcu88Vld8wkos+8++8G8qcu8bwG8++8G8qcu8==
-----END OPENSSH PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_ed25519",
			wantCount:     1,
			wantEncrypted: true,
			wantKeyType:   "OPENSSH",
			wantSeverity:  "low",
		},
		{
			name: "unencrypted EC key",
			content: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGlRjzCPJ3h8O7BDTLFjFYgKPWP3H+m7J+k2J+FhJ+k2J+FhJ+k2oAo
GCCqGSM49AwEHoUQDQgAE1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH
IJKLMNOPQRSTUVWXYZ
-----END EC PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_ecdsa",
			wantCount:     1,
			wantEncrypted: false,
			wantKeyType:   "EC",
			wantSeverity:  "critical",
		},
		{
			name: "encrypted EC key",
			content: `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,ABCDEF1234567890

MHcCAQEEIIGlRjzCPJ3h8O7BDTLFjFYgKPWP3H+m7J+k2J+FhJ+k2J+FhJ+k2oAo
GCCqGSM49AwEHoUQDQgAE1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH
IJKLMNOPQRSTUVWXYZ
-----END EC PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_ecdsa",
			wantCount:     1,
			wantEncrypted: true,
			wantKeyType:   "EC",
			wantSeverity:  "low",
		},
		{
			name: "DSA key",
			content: `-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQC1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
STUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz==
-----END DSA PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_dsa",
			wantCount:     1,
			wantEncrypted: false,
			wantKeyType:   "DSA",
			wantSeverity:  "critical",
		},
		{
			name: "encrypted private key block",
			content: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI1234567890abcCAg
gAMAwDQYJKoZIhvcNAQIFADAUBggqhkiG9w0DBwQI1234567890ab==
-----END ENCRYPTED PRIVATE KEY-----`,
			source:        "file:~/.ssh/id_encrypted",
			wantCount:     1,
			wantEncrypted: true,
			wantKeyType:   "ENCRYPTED",
			wantSeverity:  "low",
		},
		{
			name:      "no private key present",
			content:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
			source:    "file:~/.ssh/id_rsa.pub",
			wantCount: 0,
		},
		{
			name:      "empty content",
			content:   "",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name: "multiple keys in same file",
			content: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
-----END RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,ABCDEF

MHcCAQEEIIGlRjzCPJ3h8O7BDTLFjFYgKPWP3H+m7J+k2J+FhJ+k2J+FhJ+k2oAo
-----END EC PRIVATE KEY-----`,
			source:    "file:multiple_keys",
			wantCount: 2,
		},
		{
			name: "case insensitive BEGIN marker",
			content: `-----begin rsa private key-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN
OPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR
-----end rsa private key-----`,
			source:        "file:lowercase_key",
			wantCount:     1,
			wantEncrypted: false,
			wantKeyType:   "RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.Detect(tt.content, testCtx(tt.source))

			assert.Len(t, findings, tt.wantCount, "Expected %d findings", tt.wantCount)

			if tt.wantCount > 0 {
				f := findings[0]

				// Verify basic fields
				assert.NotEmpty(t, f.ID)
				assert.NotEmpty(t, f.Severity)
				assert.NotEmpty(t, f.Title)
				assert.NotEmpty(t, f.Message)
				assert.Equal(t, tt.source, f.Path)

				// Verify severity
				if tt.wantSeverity != "" {
					assert.Equal(t, tt.wantSeverity, f.Severity)
				}

				// Verify metadata
				assert.NotNil(t, f.Metadata)
				isEncrypted, ok := f.Metadata["is_encrypted"].(bool)
				require.True(t, ok, "is_encrypted not found in metadata")
				assert.Equal(t, tt.wantEncrypted, isEncrypted)

				if tt.wantKeyType != "" {
					keyType, ok := f.Metadata["key_type"].(string)
					require.True(t, ok, "key_type not found in metadata")
					assert.Equal(t, tt.wantKeyType, keyType)
				}

				detectorName, ok := f.Metadata["detector_name"].(string)
				require.True(t, ok, "detector_name not found in metadata")
				assert.Equal(t, "ssh-private-key", detectorName)
			}
		})
	}
}

func TestSSHPrivateKeyDetector_Name(t *testing.T) {
	detector := NewSSHPrivateKeyDetector()
	assert.Equal(t, "ssh-private-key", detector.Name())
}

func TestSSHPrivateKeyDetector_DetermineKeyType(t *testing.T) {
	detector := NewSSHPrivateKeyDetector()

	tests := []struct {
		name        string
		keyContent  string
		wantKeyType string
	}{
		{
			name: "RSA key",
			keyContent: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAK...
-----END RSA PRIVATE KEY-----`,
			wantKeyType: "RSA",
		},
		{
			name: "EC key",
			keyContent: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEE...
-----END EC PRIVATE KEY-----`,
			wantKeyType: "EC",
		},
		{
			name: "DSA key",
			keyContent: `-----BEGIN DSA PRIVATE KEY-----
MIIBugIB...
-----END DSA PRIVATE KEY-----`,
			wantKeyType: "DSA",
		},
		{
			name: "OPENSSH key",
			keyContent: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNz...
-----END OPENSSH PRIVATE KEY-----`,
			wantKeyType: "OPENSSH",
		},
		{
			name: "encrypted private key",
			keyContent: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBg...
-----END ENCRYPTED PRIVATE KEY-----`,
			wantKeyType: "ENCRYPTED",
		},
		{
			name: "PKCS8 private key",
			keyContent: `-----BEGIN PRIVATE KEY-----
MIIEvQIBA...
-----END PRIVATE KEY-----`,
			wantKeyType: "PKCS8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyType := detector.determineKeyType(tt.keyContent)
			assert.Equal(t, tt.wantKeyType, keyType)
		})
	}
}

func TestSSHPrivateKeyDetector_IsEncrypted(t *testing.T) {
	detector := NewSSHPrivateKeyDetector()

	tests := []struct {
		name          string
		keyContent    string
		wantEncrypted bool
	}{
		{
			name: "encrypted with Proc-Type header",
			keyContent: `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,ABCDEF

MIIEpAIBAAK...
-----END RSA PRIVATE KEY-----`,
			wantEncrypted: true,
		},
		{
			name: "encrypted OPENSSH key",
			keyContent: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDl8IT7hX
-----END OPENSSH PRIVATE KEY-----`,
			wantEncrypted: true,
		},
		{
			name: "encrypted private key block",
			keyContent: `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBg...
-----END ENCRYPTED PRIVATE KEY-----`,
			wantEncrypted: true,
		},
		{
			name: "unencrypted RSA key",
			keyContent: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAK...
-----END RSA PRIVATE KEY-----`,
			wantEncrypted: false,
		},
		{
			name: "unencrypted OPENSSH key",
			keyContent: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ...
-----END OPENSSH PRIVATE KEY-----`,
			wantEncrypted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isEncrypted := detector.isEncrypted(tt.keyContent)
			assert.Equal(t, tt.wantEncrypted, isEncrypted)
		})
	}
}

func TestSSHPrivateKeyDetector_RealWorldKeys(t *testing.T) {
	detector := NewSSHPrivateKeyDetector()

	// Test with a more realistic key structure
	rsaKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5lGJJzFvJAsjyfdhwfh/wefhwehfiwefhwefhwehfweoifhw
efhwefhweufhwefhwefhwefhwefhwefhwefhwefhwefhweufhweufhweufhweuf
hwefhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhwe
ufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweuf
hwefhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhwe
ufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweuf
hwefhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhweufhwe
-----END RSA PRIVATE KEY-----`

	findings := detector.Detect(rsaKey, testCtx("file:test_key"))
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Contains(t, findings[0].Description, "NOT password-protected")
}
