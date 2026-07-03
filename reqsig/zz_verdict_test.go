// SPDX-License-Identifier: AGPL-3.0-or-later

package reqsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func testVerdict() Verdict {
	canon, _ := testEnvelope().Canonical()
	return Verdict{
		EnvHash:       HashEnvelope(canon),
		Network:       1,
		Node:          0xABCD1234,
		Valid:         true,
		Online:        true,
		NetworkMember: false,
		LastSeenUnix:  1779999980,
		KeyGeneration: 3,
		VerifiedAt:    1780000000,
	}
}

func TestVerdictCanonicalRoundTrip(t *testing.T) {
	v := testVerdict()
	canon, err := v.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseVerdict(canon)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, v)
	}
}

func TestVerdictSignVerifyWithKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canon, sig, err := SignVerdict(priv, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyVerdictWithKey(pub, canon, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Valid || !v.Online || v.KeyGeneration != 3 {
		t.Fatalf("bad parsed verdict: %+v", v)
	}
}

func TestVerdictVerifyRejectsTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canon, sig, err := SignVerdict(priv, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	// Flip valid → invalid and online bits; both must break the signature.
	tampered := strings.Replace(canon, "|1|1|0|", "|0|1|0|", 1)
	if tampered == canon {
		t.Fatal("test setup: replacement did not apply")
	}
	if _, err := VerifyVerdictWithKey(pub, tampered, sig); err == nil {
		t.Fatal("expected verification failure on tampered verdict")
	}
}

func TestVerdictKeyringFailClosed(t *testing.T) {
	// Default build has an empty keyring: every kid must fail.
	if _, err := VerifyVerdict("vfy-v1", "x", "y"); err == nil {
		t.Fatal("expected fail-closed with empty keyring")
	}

	// Populated keyring: known kid verifies, unknown kid fails,
	// all-zero key entries are rejected.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	saved := verdictKeyringB64
	defer func() { verdictKeyringB64 = saved }()
	zero := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	verdictKeyringB64 = "vfy-v1=" + base64.StdEncoding.EncodeToString(pub) + ",vfy-zero=" + zero

	canon, sig, err := SignVerdict(priv, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerdict("vfy-v1", canon, sig); err != nil {
		t.Fatalf("known kid should verify: %v", err)
	}
	if _, err := VerifyVerdict("vfy-v2", canon, sig); err == nil {
		t.Fatal("unknown kid must fail closed")
	}
	if _, err := VerifyVerdict("vfy-zero", canon, sig); err == nil {
		t.Fatal("all-zero key must be rejected")
	}
}

func TestParseVerdictRejectsBadInputs(t *testing.T) {
	base, err := testVerdict().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"wrong domain": strings.Replace(base, VerdictDomain, "pilot-verdict-v2", 1),
		"bad bool":     strings.Replace(base, "|1|1|0|", "|2|1|0|", 1),
		"extra field":  base + "|x",
		"empty":        "",
	}
	for name, in := range cases {
		if _, err := ParseVerdict(in); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}
