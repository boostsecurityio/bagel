// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var configFileWithCreds = `{
	"auths": {
		"dhi.io": {
            "auth": "supersecret"
        },
		"docker.io": {},
		"ghcr.io": {}
	},
	"credHelpers": {
		"dhi.io": "osxkeychain",
		"ghcr.io": "osxkeychain",
        "docker.io": "osxkeychain"
	}
}
`

var configFileWithoutCreds = `{
	"auths": {
		"dhi.io": {},
		"docker.io": {},
		"ghcr.io": {}
	},
	"credHelpers": {
		"dhi.io": "osxkeychain",
		"ghcr.io": "osxkeychain",
        "docker.io": "osxkeychain"
	}
}
`

func TestParsingFileWithCreds(t *testing.T) {
	expected := []string{"dhi.io"}
	actual, _ := regsWithCreds(configFileWithCreds)
	assert.Equal(t, expected, actual)
}

func TestParsingFileWithoutCreds(t *testing.T) {
	var expected []string
	actual, _ := regsWithCreds(configFileWithoutCreds)
	assert.Equal(t, expected, actual)
}
