// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWireGuardKeyDetector_Detect(t *testing.T) {
	t.Parallel()

	det := NewWireGuardKeyDetector()

	tests := []struct {
		name      string
		content   string
		source    string
		wantCount int
	}{
		{
			name: "detect private key in interface section",
			content: `[Interface]
Address = 10.0.0.1/24
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820`,
			source:    "file:/etc/wireguard/wg0.conf",
			wantCount: 1,
		},
		{
			name:      "detect private key with spaces around equals",
			content:   "PrivateKey  =  yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
			source:    "file:~/.config/wireguard/wg0.conf",
			wantCount: 1,
		},
		{
			name:      "detect private key without spaces",
			content:   "PrivateKey=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
			source:    "file:/etc/wireguard/wg0.conf",
			wantCount: 1,
		},
		{
			name: "config with multiple sections",
			content: `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0`,
			source:    "file:/etc/wireguard/wg0.conf",
			wantCount: 1, // Only PrivateKey, not PublicKey
		},
		{
			name:      "no private key",
			content:   "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "empty string",
			content:   "",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "key too short",
			content:   "PrivateKey = abc=",
			source:    "file:test",
			wantCount: 0,
		},
		{
			name:      "duplicate keys deduplicated",
			content:   "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
			source:    "file:test",
			wantCount: 1,
		},
		{
			name:      "two different keys",
			content:   "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nPrivateKey = QHcpxU6IqhWVKPj1cOMYSg7xY3mPNB3sSf2GRYFU9HQ=",
			source:    "file:test",
			wantCount: 2,
		},
		{
			name:      "key in shell history",
			content:   "echo 'PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=' >> /etc/wireguard/wg0.conf",
			source:    "file:~/.bash_history",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := det.Detect(tt.content, testCtx(tt.source))
			assert.Len(t, findings, tt.wantCount, "Expected %d findings", tt.wantCount)

			for i, f := range findings {
				assert.Equal(t, "wireguard-private-key", f.ID, "Finding %d has wrong ID", i)
				assert.Equal(t, "critical", f.Severity)
				assert.NotEmpty(t, f.Title)
				assert.NotEmpty(t, f.Message)
				assert.Equal(t, "wireguard-key", f.Metadata["detector_name"])
				assert.Equal(t, "wireguard-private-key", f.Metadata["token_type"])
			}
		})
	}
}

func TestWireGuardKeyDetector_Redact(t *testing.T) {
	t.Parallel()

	det := NewWireGuardKeyDetector()

	tests := []struct {
		name      string
		content   string
		want      string
		wantCount int
	}{
		{
			name:      "redact private key",
			content:   "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
			want:      "PrivateKey = [REDACTED-wireguard-key]",
			wantCount: 1,
		},
		{
			name:      "no key to redact",
			content:   "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			want:      "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			wantCount: 0,
		},
		{
			name: "redact key preserving context",
			content: `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.1/24`,
			want: `[Interface]
PrivateKey = [REDACTED-wireguard-key]
Address = 10.0.0.1/24`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, counts := det.Redact(tt.content)
			assert.Equal(t, tt.want, result)

			total := 0
			for _, c := range counts {
				total += c
			}
			assert.Equal(t, tt.wantCount, total)
		})
	}
}

func TestWireGuardKeyDetector_Name(t *testing.T) {
	t.Parallel()

	det := NewWireGuardKeyDetector()
	require.Equal(t, "wireguard-key", det.Name())
}
