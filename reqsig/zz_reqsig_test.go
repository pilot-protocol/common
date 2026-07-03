// SPDX-License-Identifier: AGPL-3.0-or-later

package reqsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testEnvelope() Envelope {
	return Envelope{
		Network:   1,
		Node:      0xABCD1234,
		Timestamp: 1780000000,
		Nonce:     "0123456789abcdef",
		BodyHash:  HashBody([]byte("hello")),
		Audience:  "svc.example.io",
	}
}

func TestCanonicalRoundTrip(t *testing.T) {
	e := testEnvelope()
	canon, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := "pilot-req-v1|0001abcd1234|1780000000|0123456789abcdef|" +
		HashBody([]byte("hello")) + "|svc.example.io"
	if canon != want {
		t.Fatalf("canonical mismatch:\n got %q\nwant %q", canon, want)
	}
	got, err := Parse(canon)
	if err != nil {
		t.Fatal(err)
	}
	if got != e {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, e)
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv := testKey(t)
	canon, sig, err := Sign(priv, testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	e, err := Verify(pub, canon, sig)
	if err != nil {
		t.Fatal(err)
	}
	if e.Node != 0xABCD1234 || e.Audience != "svc.example.io" {
		t.Fatalf("bad parsed envelope: %+v", e)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := testKey(t)
	otherPub, _ := testKey(t)
	canon, sig, err := Sign(priv, testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(otherPub, canon, sig); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

func TestVerifyRejectsTamperedField(t *testing.T) {
	pub, priv := testKey(t)
	canon, sig, err := Sign(priv, testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(canon, "svc.example.io", "svc.evil.io", 1)
	if _, err := Verify(pub, tampered, sig); err == nil {
		t.Fatal("expected verification failure on tampered audience")
	}
}

func TestParseRejectsBadInputs(t *testing.T) {
	e := testEnvelope()
	base, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"wrong domain":        strings.Replace(base, "pilot-req-v1", "pilot-req-v2", 1),
		"short address":       strings.Replace(base, "0001abcd1234", "001abcd1234", 1),
		"upper hex address":   strings.Replace(base, "0001abcd1234", "0001ABCD1234", 1),
		"leading zero ts":     strings.Replace(base, "|1780000000|", "|01780000000|", 1),
		"negative ts":         strings.Replace(base, "|1780000000|", "|-178|", 1),
		"short nonce":         strings.Replace(base, "0123456789abcdef", "0123456789abcde", 1),
		"empty audience":      strings.TrimSuffix(base, "svc.example.io"),
		"audience bad chars":  strings.Replace(base, "svc.example.io", "svc|example", 1),
		"audience upper":      strings.Replace(base, "svc.example.io", "SVC.example.io", 1),
		"extra field":         base + "|x",
		"missing field":       strings.TrimSuffix(base, "|svc.example.io"),
		"empty":               "",
		"raw protocol string": "handshake:12345:67890",
	}
	for name, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("%s: expected parse error for %q", name, in)
		}
	}
}

func TestCanonicalRejectsBadFields(t *testing.T) {
	cases := map[string]Envelope{
		"bad nonce":     {Nonce: "xyz", BodyHash: HashBody(nil), Audience: "a"},
		"bad body hash": {Nonce: "0123456789abcdef", BodyHash: "beef", Audience: "a"},
		"long audience": {Nonce: "0123456789abcdef", BodyHash: HashBody(nil), Audience: strings.Repeat("a", 65)},
		"pipe audience": {Nonce: "0123456789abcdef", BodyHash: HashBody(nil), Audience: "a|b"},
	}
	for name, e := range cases {
		if _, err := e.Canonical(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestCheckFresh(t *testing.T) {
	now := time.Unix(1780000000, 0)
	e := testEnvelope()

	if err := CheckFresh(e, now, 0); err != nil {
		t.Fatalf("exact time should be fresh: %v", err)
	}
	if err := CheckFresh(e, now.Add(299*time.Second), 0); err != nil {
		t.Fatalf("inside default window: %v", err)
	}
	if err := CheckFresh(e, now.Add(301*time.Second), 0); err == nil {
		t.Fatal("expected stale past default window")
	}
	if err := CheckFresh(e, now.Add(-301*time.Second), 0); err == nil {
		t.Fatal("expected stale for future-dated envelope")
	}
	if err := CheckFresh(e, now.Add(30*time.Second), 10*time.Second); err == nil {
		t.Fatal("expected stale with tight custom window")
	}
}

func TestNewNonce(t *testing.T) {
	a, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	if !isLowerHex(a, NonceLen) || !isLowerHex(b, NonceLen) {
		t.Fatalf("nonces not canonical hex: %q %q", a, b)
	}
	if a == b {
		t.Fatal("nonces must differ")
	}
}
