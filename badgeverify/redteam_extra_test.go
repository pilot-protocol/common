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

// This file supplements redteam_test.go with the cross-type and
// non-canonical-encoding attacks that the original suite did not cover
// explicitly:
//
//   - confusion in BOTH directions across all three statement types
//   - a key that is valid in the OTHER keyring (online vs cold) must not
//     verify the wrong statement type
//   - non-canonical integer encodings (leading zeros, signs, whitespace)
//     rejected at the VERIFY boundary for all three types
//   - the all-zero placeholder key fails closed for recovery + enrollment
//     too, not just badges

// signWith returns a base64 detached signature over s.
func signWith(p ed25519.PrivateKey, s string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(p, []byte(s)))
}

// ATTACK: a legitimately-signed badge must not be accepted by the
// enrollment verifier, and a legitimately-signed enrollment must not be
// accepted by the badge or recovery verifier. (Completes the confusion
// matrix that redteam_test.go covered only for recovery<->badge.)
func TestRedteamExtra_EnrollmentConfusionBothWays(t *testing.T) {
	signBadge, _, badgePriv, _ := redteam(t)
	_ = signBadge

	// A valid enrollment under the online badge key.
	enr, err := CanonicalEnrollment(Enrollment{NodeID: 1, Provider: "github", Commitment: "C", IssuedAt: 100, Kid: "bdg"})
	if err != nil {
		t.Fatalf("canonical enrollment: %v", err)
	}
	enrSig := signWith(badgePriv, enr)
	if _, err := VerifyEnrollment(enr, enrSig); err != nil {
		t.Fatalf("control: legit enrollment should verify: %v", err)
	}

	// Enrollment must NOT verify as a badge (wrong prefix → ErrMalformed).
	if _, err := Verify(enr, enrSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("enrollment accepted as badge: %v", err)
	}
	// Enrollment must NOT verify as a recovery.
	if _, err := VerifyRecovery(enr, enrSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("enrollment accepted as recovery: %v", err)
	}

	// A valid badge must NOT verify as an enrollment.
	b, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "bdg"})
	bSig := signWith(badgePriv, b)
	if _, err := VerifyEnrollment(b, bSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("badge accepted as enrollment: %v", err)
	}
}

// ATTACK: a key that is valid in ONE keyring must not verify a statement
// routed to the OTHER keyring. The cold recovery key signs an enrollment
// naming the recovery kid; enrollment verifies against the ONLINE keyring,
// which has no "rec" entry → fail closed.
func TestRedteamExtra_WrongKeyringRejected(t *testing.T) {
	_, _, _, recPriv := redteam(t)

	// Enrollment naming the cold kid, signed by the cold key.
	enr, _ := CanonicalEnrollment(Enrollment{NodeID: 1, Provider: "github", Commitment: "C", IssuedAt: 100, Kid: "rec"})
	sig := signWith(recPriv, enr)
	// Online keyring has no "rec" → ErrNoKey, never an accidental accept.
	if _, err := VerifyEnrollment(enr, sig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("enrollment under cold kid must fail closed, got %v", err)
	}

	// And a badge naming the cold kid likewise fails closed.
	b, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "rec"})
	if _, err := Verify(b, signWith(recPriv, b)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("badge under cold kid must fail closed, got %v", err)
	}
}

// ATTACK: a key from a DIFFERENT, unrelated keyring (attacker's own pinned
// world) must not verify our statements. Generate a fresh keypair, pin it
// under the same kid name in a throwaway keyring, and confirm a signature
// from the REAL issuer no longer verifies once the pinned key is swapped.
func TestRedteamExtra_KeyFromOtherKeyringRejected(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	b, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "bdg"})
	goodSig := signBadge(b)
	if _, err := Verify(b, goodSig); err != nil {
		t.Fatalf("control: should verify under real key: %v", err)
	}

	// Swap the pinned "bdg" key for an unrelated one; the real signature
	// must now be rejected (proves verify is bound to the pinned key, not
	// merely to any key named "bdg").
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	orig := keyringB64
	keyringB64 = "bdg=" + base64.StdEncoding.EncodeToString(otherPub)
	t.Cleanup(func() { keyringB64 = orig })
	if _, err := Verify(b, goodSig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature must not verify under a different pinned key, got %v", err)
	}
}

// ATTACK: non-canonical integer encodings must be rejected at the VERIFY
// boundary for ALL THREE statement types — even when correctly signed —
// because the signed bytes are the non-canonical form and the parser must
// refuse the alternate encoding (no malleable second representation).
func TestRedteamExtra_NonCanonicalIntegersRejected(t *testing.T) {
	signBadge, signRecover, badgePriv, _ := redteam(t)
	_ = signBadge

	// Each entry is a hand-built wire string with a non-canonical integer.
	// We sign the exact bytes (hostile issuer) and confirm parse/verify
	// still rejects them as malformed.
	type tc struct {
		name string
		s    string
		verA func(s, sig string) error
	}
	verBadge := func(s, sig string) error { _, e := Verify(s, sig); return e }
	verEnr := func(s, sig string) error { _, e := VerifyEnrollment(s, sig); return e }
	verRec := func(s, sig string) error { _, e := VerifyRecovery(s, sig); return e }

	cases := []tc{
		// Badge: leading-zero / signed / whitespace integers.
		{"badge leading-zero node", "pilotbadge:" + Version + ":01:github:0:0:bdg:", verBadge},
		{"badge signed node", "pilotbadge:" + Version + ":+1:github:0:0:bdg:", verBadge},
		{"badge leading-zero verifiedat", "pilotbadge:" + Version + ":1:github:00:0:bdg:", verBadge},
		{"badge whitespace exp", "pilotbadge:" + Version + ":1:github:0: 1:bdg:", verBadge},
		// Enrollment.
		{"enroll leading-zero node", "pilotenroll:" + Version + ":01:github:C:0:bdg", verEnr},
		{"enroll signed issuedat", "pilotenroll:" + Version + ":1:github:C:+5:bdg", verEnr},
		// Recovery.
		{"recover leading-zero node", "pilotrecover:" + Version + ":01:np:C:1:n:rec", verRec},
		{"recover leading-zero exp", "pilotrecover:" + Version + ":1:np:C:01:n:rec", verRec},
	}

	signFor := func(s string) string {
		// recovery strings are signed by the cold key, everything else by online.
		if len(s) >= len(prefixRecover) && s[:len(prefixRecover)] == prefixRecover {
			return signRecover(s)
		}
		return signWith(badgePriv, s)
	}

	for _, c := range cases {
		if err := c.verA(c.s, signFor(c.s)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: non-canonical integer must be rejected as malformed, got %v", c.name, err)
		}
	}
}

// ATTACK: the all-zero placeholder key (forgot the -ldflags override) must
// fail closed for recovery and enrollment too, not just badges.
func TestRedteamExtra_PlaceholderKeyFailsClosedAllTypes(t *testing.T) {
	// Restore the compiled-in all-zero placeholders for the duration.
	origK, origR := keyringB64, recoveryKeyringB64
	keyringB64 = "v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	recoveryKeyringB64 = "rec-v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	t.Cleanup(func() { keyringB64, recoveryKeyringB64 = origK, origR })

	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	enr, _ := CanonicalEnrollment(Enrollment{NodeID: 1, Provider: "github", Commitment: "C", IssuedAt: 1, Kid: "v1"})
	if _, err := VerifyEnrollment(enr, signWith(priv, enr)); !errors.Is(err, ErrNoKey) {
		t.Errorf("enrollment under placeholder key must fail closed, got %v", err)
	}

	rec, _ := CanonicalRecovery(Recovery{NodeID: 1, NewPubKey: "np", Commitment: "C", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n", Kid: "rec-v1"})
	if _, err := VerifyRecovery(rec, signWith(priv, rec)); !errors.Is(err, ErrNoKey) {
		t.Errorf("recovery under placeholder key must fail closed, got %v", err)
	}
}

// ATTACK: a never-expiring badge is ALLOWED (Exp==0 means no expiry) and
// must verify; a never-expiring recovery is DISALLOWED and must be rejected
// even when correctly signed. Pins the asymmetry the spec requires.
func TestRedteamExtra_NeverExpiringPolicyAsymmetry(t *testing.T) {
	signBadge, signRecover, _, _ := redteam(t)

	// Badge with Exp==0 verifies (no-expiry is a legitimate badge).
	b, _ := Canonical(Badge{NodeID: 1, Provider: "github", Exp: 0, Kid: "bdg"})
	if _, err := Verify(b, signBadge(b)); err != nil {
		t.Fatalf("no-expiry badge must verify, got %v", err)
	}

	// Recovery with exp=0, signed correctly by the cold key, must be rejected.
	rec := "pilotrecover:" + Version + ":1:np:C:0:n:rec"
	if _, err := VerifyRecovery(rec, signRecover(rec)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no-expiry recovery must be rejected even when signed, got %v", err)
	}
}

// ATTACK: node-binding mismatch with a CORRECTLY signed badge — the
// signature is valid but the badge is bound to a different node than the
// authenticated peer. (redteam_test.go covers the unsigned-replay path;
// this pins the signed-but-wrong-node path through VerifyForNode.)
func TestRedteamExtra_SignedBadgeWrongNodeRejected(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	b, _ := Canonical(Badge{NodeID: 0x1234, Provider: "github", Kid: "bdg"})
	sig := signBadge(b)
	if _, err := VerifyForNode(b, sig, 0x1234); err != nil {
		t.Fatalf("matching node must verify, got %v", err)
	}
	if _, err := VerifyForNode(b, sig, 0x5678); !errors.Is(err, ErrNodeMismatch) {
		t.Fatalf("signed badge bound to wrong node must fail, got %v", err)
	}
}
