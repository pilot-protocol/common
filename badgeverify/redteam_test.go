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

// redteam installs a two-key world: an ONLINE badge key (kid "bdg") and a
// separate COLD recovery key (kid "rec"), returning a signer for each. This
// mirrors production: badges/enrollments under the online key, recoveries
// under the cold key only.
func redteam(t *testing.T) (signBadge, signRecover func(s string) string, badgePriv, recPriv ed25519.PrivateKey) {
	t.Helper()
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	rPub, rPriv, _ := ed25519.GenerateKey(rand.Reader)

	origK, origR := keyringB64, recoveryKeyringB64
	keyringB64 = "bdg=" + base64.StdEncoding.EncodeToString(bPub)
	recoveryKeyringB64 = "rec=" + base64.StdEncoding.EncodeToString(rPub)
	t.Cleanup(func() { keyringB64, recoveryKeyringB64 = origK, origR })

	mk := func(p ed25519.PrivateKey) func(string) string {
		return func(s string) string { return base64.StdEncoding.EncodeToString(ed25519.Sign(p, []byte(s))) }
	}
	return mk(bPriv), mk(rPriv), bPriv, rPriv
}

// ATTACK: forge a badge with an attacker key the verifier doesn't pin.
func TestRedteam_ForgedBadgeRejected(t *testing.T) {
	redteam(t)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "bdg"})
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(attackerPriv, []byte(s)))
	if _, err := Verify(s, forged); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged badge must be rejected, got %v", err)
	}
}

// ATTACK: tamper each field of a legitimately-signed badge.
func TestRedteam_TamperedBadgeRejected(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	orig := Badge{NodeID: 1, Provider: "github", VerifiedAt: 100, Exp: 0, Kid: "bdg"}
	s, _ := Canonical(orig)
	sig := signBadge(s)

	tampers := []Badge{
		{NodeID: 2, Provider: "github", VerifiedAt: 100, Kid: "bdg"},                  // escalate node
		{NodeID: 1, Provider: "workos", VerifiedAt: 100, Kid: "bdg"},                  // upgrade provider
		{NodeID: 1, Provider: "github", VerifiedAt: 999, Kid: "bdg"},                  // backdate
		{NodeID: 1, Provider: "github", VerifiedAt: 100, Subject: "acme", Kid: "bdg"}, // inject label
	}
	for _, tb := range tampers {
		ts, _ := Canonical(tb)
		if _, err := Verify(ts, sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("tampered badge %+v must fail, got %v", tb, err)
		}
	}
}

// ATTACK: steal a valid badge and present it as your own node.
func TestRedteam_BadgeReplayToOtherNodeRejected(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	s, _ := Canonical(Badge{NodeID: 0xAAAA, Provider: "github", Kid: "bdg"})
	sig := signBadge(s)
	if _, err := VerifyForNode(s, sig, 0xBBBB); !errors.Is(err, ErrNodeMismatch) {
		t.Fatalf("badge replay to another node must fail, got %v", err)
	}
}

// ATTACK: relabel a badge's kid to the recovery kid to dodge key controls.
func TestRedteam_KidSwapRejected(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	// Sign under the badge key but claim kid "rec".
	s, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "rec"})
	sig := signBadge(s)
	// Badge verify uses the ONLINE keyring, which has no "rec" → fail closed.
	if _, err := Verify(s, sig); !errors.Is(err, ErrNoKey) {
		t.Fatalf("kid-swap to recovery kid must fail closed, got %v", err)
	}
}

// ATTACK (marquee): cross-statement confusion. A signature over one
// credential type must never validate as another.
func TestRedteam_CrossStatementConfusionRejected(t *testing.T) {
	signBadge, signRecover, _, _ := redteam(t)

	// A valid recovery, signed by the cold key.
	rec, _ := CanonicalRecovery(Recovery{NodeID: 1, NewPubKey: "np", Commitment: "C", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n1", Kid: "rec"})
	recSig := signRecover(rec)
	if _, err := VerifyRecovery(rec, recSig); err != nil {
		t.Fatalf("control: legit recovery should verify: %v", err)
	}
	// The recovery string/sig must NOT parse or verify as a badge or enrollment.
	if _, err := Verify(rec, recSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("recovery accepted as badge: %v", err)
	}
	if _, err := VerifyEnrollment(rec, recSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("recovery accepted as enrollment: %v", err)
	}

	// And a badge must never be accepted as a recovery authorization.
	b, _ := Canonical(Badge{NodeID: 1, Provider: "github", Kid: "bdg"})
	bSig := signBadge(b)
	if _, err := VerifyRecovery(b, bSig); !errors.Is(err, ErrMalformed) {
		t.Errorf("badge accepted as recovery: %v", err)
	}
}

// ATTACK (marquee): the online badge key must NOT be able to mint a
// recovery — that is the whole point of the cold-key split.
func TestRedteam_OnlineKeyCannotForgeRecovery(t *testing.T) {
	signBadge, _, _, _ := redteam(t)
	// Craft a recovery that NAMES the recovery kid but is signed by the
	// online badge key. Recovery verifies against the cold keyring only.
	rec, _ := CanonicalRecovery(Recovery{NodeID: 1, NewPubKey: "np", Commitment: "C", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n", Kid: "rec"})
	forged := signBadge(rec)
	if _, err := VerifyRecovery(rec, forged); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("badge key must not be able to sign a recovery, got %v", err)
	}
	// And naming the badge kid in a recovery fails closed (no such cold key).
	rec2, _ := CanonicalRecovery(Recovery{NodeID: 1, NewPubKey: "np", Commitment: "C", Exp: time.Now().Add(time.Minute).Unix(), Nonce: "n", Kid: "bdg"})
	if _, err := VerifyRecovery(rec2, signBadge(rec2)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("recovery under badge kid must fail closed, got %v", err)
	}
}

// ATTACK: a never-expiring recovery (permanent replayable takeover token).
func TestRedteam_RecoveryMustExpire(t *testing.T) {
	_, signRecover, _, _ := redteam(t)
	// CanonicalRecovery refuses exp<=0; build the wire string by hand to
	// simulate a hostile issuer/tamper, then verify it is rejected.
	s := "pilotrecover:" + Version + ":1:np:C:0:n:rec"
	if _, err := verifyRecoveryAt(s, signRecover(s), time.Now()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("recovery with exp=0 must be rejected, got %v", err)
	}
}

// ATTACK: replay an expired recovery authorization.
func TestRedteam_ExpiredRecoveryRejected(t *testing.T) {
	_, signRecover, _, _ := redteam(t)
	rec, _ := CanonicalRecovery(Recovery{NodeID: 1, NewPubKey: "np", Commitment: "C", Exp: 1000, Nonce: "n", Kid: "rec"})
	sig := signRecover(rec)
	if _, err := verifyRecoveryAt(rec, sig, time.Unix(1001, 0)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired recovery must be rejected, got %v", err)
	}
}

// ATTACK: malformed / oversized / garbage inputs must never panic and must
// fail closed across all three verifiers.
func TestRedteam_MalformedInputsNoPanic(t *testing.T) {
	redteam(t)
	junk := []string{
		"", ":", "::::::::", "pilotbadge", "pilotrecover:v1:1:np:C:notanint:n:rec",
		"pilotbadge:v1:99999999999999999999:github:0:0:bdg:", // node overflow
		string(make([]byte, 4096)),
	}
	for _, j := range junk {
		// Must return an error, never panic.
		_, _ = Verify(j, "")
		_, _ = VerifyEnrollment(j, "")
		_, _ = VerifyRecovery(j, "")
		_, _ = Verify(j, "!!!notbase64")
	}
}
