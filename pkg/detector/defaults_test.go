// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDefaultRegistry pins the built-in detector set and its registration
// order. A newly added detector that isn't wired into NewDefaultRegistry fails
// this test — order matters because scrub applies detectors in order.
func TestNewDefaultRegistry(t *testing.T) {
	t.Parallel()

	want := []string{
		"github-token",
		"npm-token",
		"ssh-private-key",
		"ai-service",
		"http-authentication",
		"cloud-credentials",
		"vault-token",
		"pypi-token",
		"wireguard-key",
		"splunk-token",
		"database-connection-string",
		"slack-token",
		"stripe-key",
		"twilio-key",
		"generic-api-key",
		"jwt",
	}

	dets := NewDefaultRegistry().GetDetectors()
	require.Len(t, dets, len(want), "default detector count changed")

	got := make([]string, len(dets))
	for i, d := range dets {
		got[i] = d.Name()
	}
	assert.Equal(t, want, got, "default detector set/order changed")
}
