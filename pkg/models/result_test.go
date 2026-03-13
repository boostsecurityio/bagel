// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		fp1 := Fingerprint("secret-value")
		fp2 := Fingerprint("secret-value")
		assert.Equal(t, fp1, fp2)
	})

	t.Run("different values produce different fingerprints", func(t *testing.T) {
		t.Parallel()
		fp1 := Fingerprint("secret-a")
		fp2 := Fingerprint("secret-b")
		assert.NotEqual(t, fp1, fp2)
	})
}

func TestSaltedFingerprint(t *testing.T) {
	t.Parallel()

	t.Run("salt changes the fingerprint", func(t *testing.T) {
		t.Parallel()
		unsalted := SaltedFingerprint("secret", "")
		salted := SaltedFingerprint("secret", "darwin:arm64:myhost:user")
		assert.NotEqual(t, unsalted, salted)
	})

	t.Run("different salts produce different fingerprints", func(t *testing.T) {
		t.Parallel()
		fp1 := SaltedFingerprint("secret", "darwin:arm64:host1:alice")
		fp2 := SaltedFingerprint("secret", "linux:amd64:host2:bob")
		assert.NotEqual(t, fp1, fp2)
	})

	t.Run("same salt and value is deterministic", func(t *testing.T) {
		t.Parallel()
		fp1 := SaltedFingerprint("secret", "darwin:arm64:myhost:user")
		fp2 := SaltedFingerprint("secret", "darwin:arm64:myhost:user")
		assert.Equal(t, fp1, fp2)
	})

	t.Run("differs from plain Fingerprint of salt:value", func(t *testing.T) {
		t.Parallel()
		salted := SaltedFingerprint("secret", "salt")
		manual := Fingerprint("salt:secret")
		assert.NotEqual(t, salted, manual, "HMAC output must differ from naive concatenation")
	})
}

func TestHostInfoFingerprintSalt(t *testing.T) {
	t.Parallel()

	t.Run("joins fields with colon separator", func(t *testing.T) {
		t.Parallel()
		h := HostInfo{OS: "darwin", Arch: "arm64", Hostname: "myhost", Username: "alice"}
		assert.Equal(t, "darwin:arm64:myhost:alice", h.FingerprintSalt())
	})

	t.Run("handles empty fields", func(t *testing.T) {
		t.Parallel()
		h := HostInfo{OS: "linux", Arch: "amd64"}
		assert.Equal(t, "linux:amd64::", h.FingerprintSalt())
	})
}

func TestFindingTypeConstants(t *testing.T) {
	t.Parallel()

	t.Run("secret type has expected value", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, FindingTypeSecret, FindingType("secret"))
	})

	t.Run("misconfiguration type has expected value", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, FindingTypeMisconfiguration, FindingType("misconfiguration"))
	})
}

func TestFingerprintFromFields(t *testing.T) {
	t.Parallel()

	t.Run("deterministic", func(t *testing.T) {
		t.Parallel()
		fp1 := FingerprintFromFields("git-ssl-verify-disabled", "git-config:http.sslverify")
		fp2 := FingerprintFromFields("git-ssl-verify-disabled", "git-config:http.sslverify")
		assert.Equal(t, fp1, fp2)
	})

	t.Run("different fields produce different fingerprints", func(t *testing.T) {
		t.Parallel()
		fp1 := FingerprintFromFields("finding-a", "path-a")
		fp2 := FingerprintFromFields("finding-b", "path-b")
		assert.NotEqual(t, fp1, fp2)
	})
}
