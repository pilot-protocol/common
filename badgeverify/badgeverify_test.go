// SPDX-License-Identifier: AGPL-3.0-or-later

package badgeverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// newIssuer generates a throwaway issuer key and installs it in the
// keyring under the given kid for the duration of a test.
func newIssuer(t *testing.T, kid string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	orig := keyringB64
	keyringB64 = kid + "=" + base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { keyringB64 = orig })
	return priv
}

// sign produces the wire (badgeStr, sigB64) for a badge, the way the
// issuer sidecar will.
func sign(t *testing.T, priv ed25519.PrivateKey, b Badge) (string, string) {
	t.Helper()
	s, err := Canonical(b)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(priv, []byte(s))
	return s, base64.StdEncoding.EncodeToString(sig)
}

func validBadge() Badge {
	return Badge{NodeID: 0x1ABCD, Provider: "github", VerifiedAt: 1700000000, Exp: 0, Kid: "v1"}
}

func TestCanonicalRoundTrip(t *testing.T) {
	b := validBadge()
	b.Subject = "acme-corp"
	s, err := Canonical(b)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	got, err := Parse(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != b {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, b)
	}
}

func TestVerifyHappyPath(t *testing.T) {
	priv := newIssuer(t, "v1")
	s, sig := sign(t, priv, validBadge())

	b, err := Verify(s, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.NodeID != 0x1ABCD || b.Provider != "github" {
		t.Fatalf("unexpected decoded badge: %+v", b)
	}
}

func TestVerifyForNodeBinding(t *testing.T) {
	priv := newIssuer(t, "v1")
	s, sig := sign(t, priv, validBadge())

	if _, err := VerifyForNode(s, sig, 0x1ABCD); err != nil {
		t.Fatalf("matching node should verify: %v", err)
	}
	// Replay onto a different node must fail even though the signature is valid.
	if _, err := VerifyForNode(s, sig, 0x99999); !errors.Is(err, ErrNodeMismatch) {
		t.Fatalf("want ErrNodeMismatch, got %v", err)
	}
}

func TestTamperedFieldFailsSignature(t *testing.T) {
	priv := newIssuer(t, "v1")
	_, sig := sign(t, priv, validBadge())

	// Forge a higher-privilege provider by editing the signed string.
	tampered := Badge{NodeID: 0x1ABCD, Provider: "workos", VerifiedAt: 1700000000, Kid: "v1"}
	ts, _ := Canonical(tampered)
	if _, err := Verify(ts, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered badge must fail signature, got %v", err)
	}
}

func TestUnknownKidFailsClosed(t *testing.T) {
	priv := newIssuer(t, "v1")
	b := validBadge()
	b.Kid = "v2" // not in the keyring
	s, sig := sign(t, priv, b)
	if _, err := Verify(s, sig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("unknown kid must fail closed with ErrNoKey, got %v", err)
	}
}

func TestPlaceholderKeyFailsClosed(t *testing.T) {
	// With the compiled-in all-zeros placeholder, verification must fail
	// CLOSED with ErrNoKey — never attempting an ed25519.Verify against the
	// low-order zero key. Guards against shipping without the -ldflags
	// issuer-key override.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, sig := sign(t, priv, validBadge())
	if _, err := Verify(s, sig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("placeholder keyring must fail closed with ErrNoKey, got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	priv := newIssuer(t, "v1")
	b := validBadge()
	b.Exp = 1700000000 // in the past relative to now
	s, sig := sign(t, priv, b)
	if _, err := verifyAt(s, sig, time.Unix(1700000001, 0)); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	if _, err := verifyAt(s, sig, time.Unix(1699999999, 0)); err != nil {
		t.Fatalf("not-yet-expired badge should verify: %v", err)
	}
}

func TestMalformed(t *testing.T) {
	cases := []string{
		"",
		"nope:v1:1:github:0:0:v1:",
		"pilotbadge:v9:1:github:0:0:v1:",
		"pilotbadge:v1:notanumber:github:0:0:v1:",
		"pilotbadge:v1:1:github:0:0:v1", // 7 fields
	}
	for _, c := range cases {
		if _, err := Parse(c); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q): want ErrMalformed, got %v", c, err)
		}
	}
}

func TestColonRejectedInFields(t *testing.T) {
	b := validBadge()
	b.Subject = "ev:il"
	if _, err := Canonical(b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("colon in subject must be rejected, got %v", err)
	}
}
