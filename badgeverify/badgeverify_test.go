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

func TestIssuerKeyPinned(t *testing.T) {
	// The production badge issuer key (kid bdg-v1) is pinned in the compiled-in
	// keyring. Confirm it is present and is NOT the all-zero placeholder, and
	// that a badge bearing kid bdg-v1 but signed by a FOREIGN key is rejected
	// with ErrBadSignature — i.e. a real ed25519.Verify runs against the pinned
	// key, rather than failing closed with ErrNoKey (which would mean the key
	// was never pinned).
	pk := keyFor("bdg-v1")
	if pk == nil {
		t.Fatal("bdg-v1 issuer key is not pinned in the compiled-in keyring")
	}
	if isAllZero(pk) {
		t.Fatal("bdg-v1 issuer key is still the all-zero placeholder")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := validBadge()
	b.Kid = "bdg-v1"
	s, sig := sign(t, priv, b)
	if _, err := Verify(s, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign-signed badge under the pinned kid must fail with ErrBadSignature, got %v", err)
	}
}

func TestPinnedIssuerGoldenVector(t *testing.T) {
	// A real badge signed by the production KMS issuer key (bdg-v1) must verify
	// against the pinned public key. This vector was produced with
	// `gcloud kms asymmetric-sign` (key ring pilot-badges/badge-issuer) over the
	// canonical badge below; baking it in locks down that genuine KMS signatures
	// validate offline — with no KMS access required at test time.
	const badge = "pilotbadge:v1:12345:github:1781827200:0:bdg-v1:"
	const sig = "Gt7fdGmEYppTEFGSRIGsjb79ol6vffH1kinMgbis3ok6uCOPKyVSuDivgiCPlqNod9/X7CK9FiCLS+5YlFVVBg=="

	b, err := Verify(badge, sig)
	if err != nil {
		t.Fatalf("KMS-signed golden badge must verify against the pinned key: %v", err)
	}
	if b.NodeID != 12345 || b.Provider != "github" || b.Kid != "bdg-v1" {
		t.Fatalf("unexpected parsed badge: %+v", b)
	}
	// Node-binding rule: the same vector binds to node 12345 and no other.
	if _, err := VerifyForNode(badge, sig, 12345); err != nil {
		t.Errorf("VerifyForNode(12345) should pass: %v", err)
	}
	if _, err := VerifyForNode(badge, sig, 99999); !errors.Is(err, ErrNodeMismatch) {
		t.Errorf("VerifyForNode(99999) must fail ErrNodeMismatch, got %v", err)
	}
}

func TestRecoveryKeyPinned(t *testing.T) {
	// The cold recovery-authority key (rec-v1) is pinned in the SEPARATE
	// recovery keyring. Confirm it is present, non-zero, and DISTINCT from the
	// badge issuer key (the two-key separation: a badge-key compromise must not
	// forge a recovery).
	pk := recoveryKeyFor("rec-v1")
	if pk == nil {
		t.Fatal("rec-v1 recovery key is not pinned in the recovery keyring")
	}
	if isAllZero(pk) {
		t.Fatal("rec-v1 recovery key is still the all-zero placeholder")
	}
	if bk := keyFor("bdg-v1"); bk != nil && pk.Equal(bk) {
		t.Fatal("recovery key must NOT equal the badge issuer key (separation broken)")
	}
}

func TestPinnedRecoveryGoldenVector(t *testing.T) {
	// A real recovery authorization signed by the KMS recovery-authority key
	// must verify against the pinned rec-v1 key. This vector was produced with
	// `gcloud kms asymmetric-sign` (key ring pilot-recovery/recovery-authority)
	// over the canonical recovery statement below (exp far in the future so the
	// vector never expires). Locks down that genuine KMS recovery signatures
	// validate offline, no KMS access at test time.
	const stmt = "pilotrecover:v1:12345:bmV3cHVi:Y29tbWl0:9999999999:nonce123:rec-v1"
	const sig = "BIjylWm38saYiXT+KIVf3Ye4WMSFb5y8UfhFo5FyCnvJLdFMEg05JmbXR0CikvT0BzYDoICaz1kvIEWg0KPGCg=="

	rec, err := VerifyRecovery(stmt, sig)
	if err != nil {
		t.Fatalf("KMS-signed recovery vector must verify against pinned rec-v1: %v", err)
	}
	if rec.NodeID != 12345 || rec.Kid != "rec-v1" || rec.Exp != 9999999999 {
		t.Fatalf("unexpected parsed recovery: %+v", rec)
	}
	// A badge (online-key) signature must NOT satisfy recovery verification —
	// recovery checks the cold keyring exclusively.
	if _, err := VerifyRecovery(stmt, "AAAA"); err == nil {
		t.Error("a non-recovery-key signature must fail recovery verification")
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

// TestRejectsNonCanonicalBadge pins the malleability guard: a badge whose
// encoding does not round-trip through Canonical (e.g. a leading-zero node_id)
// is rejected as malformed BEFORE the signature is even checked.
func TestRejectsNonCanonicalBadge(t *testing.T) {
	priv := newIssuer(t, "v1")
	// validBadge() fields, but node_id 109517 written as "0109517".
	nonCanon := "pilotbadge:v1:0109517:github:1700000000:0:v1:"
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(nonCanon)))
	if _, err := Verify(nonCanon, sig); !errors.Is(err, ErrMalformed) {
		t.Fatalf("non-canonical badge must reject with ErrMalformed, got %v", err)
	}
	// The canonical form of the same badge still verifies.
	canon, _ := Canonical(validBadge())
	csig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(canon)))
	if _, err := Verify(canon, csig); err != nil {
		t.Fatalf("canonical badge must still verify: %v", err)
	}
}
