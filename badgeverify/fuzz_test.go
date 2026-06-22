// SPDX-License-Identifier: AGPL-3.0-or-later

package badgeverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// The fuzz suite drives the THREE parsers and the THREE verifiers with
// adversarial input. Two invariants are asserted everywhere:
//
//  1. No panic. A parser/verifier handed hostile bytes must return an
//     error, never crash — these run on untrusted, attacker-controlled
//     wire data.
//  2. Fail-closed + canonical round-trip. Anything a parser ACCEPTS must
//     re-encode to the exact bytes it was handed (no malleability: a second
//     encoding of the same logical value must not exist), and no verifier
//     ever returns success for input that was not signed by a pinned key.
//
// Seeds are deterministic and small so the corpus stays reproducible and
// the CI fuzz window finds the interesting branches fast.

// seedBadges returns canonical + a few near-miss badge strings.
func seedBadges() []string {
	return []string{
		"pilotbadge:v1:1:github:0:0:v1:",
		"pilotbadge:v1:109517:github:1700000000:0:v1:acme-corp",
		"pilotbadge:v1:4294967295:google:1700000000:1800000000:v1:label",
		"pilotbadge:v1:0:workos:0:0:v1:",
		// near-misses / malleability probes
		"pilotbadge:v1:01:github:0:0:v1:",  // leading-zero node_id
		"pilotbadge:v1:+1:github:0:0:v1:",  // signed integer form
		"pilotbadge:v1:1:github:00:0:v1:",  // leading-zero verified_at
		"pilotbadge:v1:1:github:0:-0:v1:",  // negative-zero exp
		"pilotbadge:v1:1:github: 1:0:v1:",  // whitespace integer
		"pilotbadge:v0:1:github:0:0:v1:",   // wrong version
		"notpilot:v1:1:github:0:0:v1:",     // wrong prefix
		"pilotbadge:v1:1:github:0:0:v1",    // too few fields
		"pilotbadge:v1:1:github:0:0:v1::x", // too many fields
		"",
		"::::::::",
	}
}

func seedEnrollments() []string {
	return []string{
		"pilotenroll:v1:1:github:Y29tbWl0:1700000000:v1",
		"pilotenroll:v1:4294967295:google:abc:0:v1",
		"pilotenroll:v1:01:github:c:0:v1",  // leading-zero node_id
		"pilotenroll:v1:1:github:c:+5:v1",  // signed issued_at
		"pilotbadge:v1:1:github:0:0:v1:",   // wrong type (cross-confusion)
		"pilotenroll:v1:1::c:0:v1",         // empty provider
		"pilotenroll:v1:1:github:c:0:v1:x", // too many fields
		"",
	}
}

func seedRecoveries() []string {
	return []string{
		"pilotrecover:v1:1:bmV3a2V5:Y29tbWl0:1800000000:nonce1:rec",
		"pilotrecover:v1:4294967295:np:C:1:n:rec",
		"pilotrecover:v1:01:np:C:1:n:rec",      // leading-zero node_id
		"pilotrecover:v1:1:np:C:01:n:rec",      // leading-zero exp
		"pilotrecover:v1:1:np:C:0:n:rec",       // exp=0 (forbidden)
		"pilotrecover:v1:1:np:C:-1:n:rec",      // negative exp
		"pilotbadge:v1:1:github:0:0:v1:",       // wrong type (cross-confusion)
		"pilotrecover:v1:1:np::1:n:rec",        // empty commitment
		"pilotrecover:v1:1:np:C:1:n:rec:extra", // too many fields
		"",
	}
}

// FuzzParseBadge asserts Parse never panics and that any accepted badge
// re-encodes to the EXACT input (canonical, non-malleable).
func FuzzParseBadge(f *testing.F) {
	for _, s := range seedBadges() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Parse(s)
		if err != nil {
			return
		}
		got, cErr := Canonical(b)
		if cErr != nil {
			t.Fatalf("Parse accepted %q but Canonical rejected the parsed value: %v", s, cErr)
		}
		if got != s {
			t.Fatalf("malleability: Parse(%q) re-encodes to %q (a non-canonical form was accepted)", s, got)
		}
	})
}

// FuzzParseEnrollment: same round-trip guard for enrollments.
func FuzzParseEnrollment(f *testing.F) {
	for _, s := range seedEnrollments() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEnrollment(s)
		if err != nil {
			return
		}
		got, cErr := CanonicalEnrollment(e)
		if cErr != nil {
			t.Fatalf("ParseEnrollment accepted %q but CanonicalEnrollment rejected it: %v", s, cErr)
		}
		if got != s {
			t.Fatalf("malleability: ParseEnrollment(%q) re-encodes to %q", s, got)
		}
	})
}

// FuzzParseRecovery: same round-trip guard for recovery authorizations.
func FuzzParseRecovery(f *testing.F) {
	for _, s := range seedRecoveries() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRecovery(s)
		if err != nil {
			return
		}
		got, cErr := CanonicalRecovery(r)
		if cErr != nil {
			t.Fatalf("ParseRecovery accepted %q but CanonicalRecovery rejected it: %v", s, cErr)
		}
		if got != s {
			t.Fatalf("malleability: ParseRecovery(%q) re-encodes to %q", s, got)
		}
	})
}

// fuzzKeyring installs a real keyring (online "v1", cold "rec") for the
// verify fuzzers so they exercise the full signature path, not just the
// no-key short-circuit. Reset after the run.
func fuzzKeyring(f *testing.F) {
	f.Helper()
	oPub, _, _ := ed25519.GenerateKey(rand.Reader)
	rPub, _, _ := ed25519.GenerateKey(rand.Reader)
	origK, origR := keyringB64, recoveryKeyringB64
	keyringB64 = "v1=" + base64.StdEncoding.EncodeToString(oPub)
	recoveryKeyringB64 = "rec=" + base64.StdEncoding.EncodeToString(rPub)
	f.Cleanup(func() { keyringB64, recoveryKeyringB64 = origK, origR })
}

// FuzzVerify drives Verify with arbitrary (badge, sig) pairs. A pinned key
// exists but the adversary does not hold its private half, so Verify must
// NEVER succeed (fail-closed) and must never panic.
func FuzzVerify(f *testing.F) {
	fuzzKeyring(f)
	for _, s := range seedBadges() {
		f.Add(s, "")
		f.Add(s, "!!notbase64")
		f.Add(s, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	}
	f.Fuzz(func(t *testing.T, badge, sig string) {
		if _, err := Verify(badge, sig); err == nil {
			t.Fatalf("Verify returned success for unsigned input: badge=%q sig=%q", badge, sig)
		}
		// VerifyForNode is Verify plus a binding check; it must also stay closed.
		if _, err := VerifyForNode(badge, sig, 1); err == nil {
			t.Fatalf("VerifyForNode returned success for unsigned input: badge=%q sig=%q", badge, sig)
		}
	})
}

// FuzzVerifyEnrollment: enrollment verifier must fail-closed for garbage.
func FuzzVerifyEnrollment(f *testing.F) {
	fuzzKeyring(f)
	for _, s := range seedEnrollments() {
		f.Add(s, "")
		f.Add(s, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	}
	f.Fuzz(func(t *testing.T, s, sig string) {
		if _, err := VerifyEnrollment(s, sig); err == nil {
			t.Fatalf("VerifyEnrollment returned success for unsigned input: s=%q sig=%q", s, sig)
		}
	})
}

// FuzzVerifyRecovery: recovery verifier must fail-closed for garbage, AND a
// badge-shaped string must never sneak through (cross-statement defense).
func FuzzVerifyRecovery(f *testing.F) {
	fuzzKeyring(f)
	for _, s := range append(seedRecoveries(), seedBadges()...) {
		f.Add(s, "")
		f.Add(s, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	}
	f.Fuzz(func(t *testing.T, s, sig string) {
		if _, err := VerifyRecovery(s, sig); err == nil {
			t.Fatalf("VerifyRecovery returned success for unsigned input: s=%q sig=%q", s, sig)
		}
	})
}
