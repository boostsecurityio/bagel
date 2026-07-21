// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: GPL-3.0-or-later

package detector

// NewDefaultRegistry returns a Registry with all built-in detectors registered,
// in the same order the bagel CLI uses. Registration order is significant for
// redaction (scrub applies detectors in order), so keep it stable.
func NewDefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewGitHubPATDetector())
	r.Register(NewNPMTokenDetector())
	r.Register(NewSSHPrivateKeyDetector())
	r.Register(NewAIServiceDetector())
	r.Register(NewHTTPAuthDetector())
	r.Register(NewCloudCredentialsDetector())
	r.Register(NewVaultTokenDetector())
	r.Register(NewPyPITokenDetector())
	r.Register(NewWireGuardKeyDetector())
	r.Register(NewSplunkTokenDetector())
	r.Register(NewDatabaseConnectionDetector())
	r.Register(NewSlackTokenDetector())
	r.Register(NewStripeKeyDetector())
	r.Register(NewTwilioKeyDetector())
	r.Register(NewGenericAPIKeyDetector())
	r.Register(NewJWTDetector())
	return r
}
