// SPDX-License-Identifier: AGPL-3.0-or-later

package reqsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignRejectsInvalidEnvelope(t *testing.T) {
	_, priv := testKey(t)
	e := testEnvelope()
	e.Nonce = "not-hex"
	if _, _, err := Sign(priv, e); err == nil {
		t.Fatal("expected Sign to reject an invalid envelope")
	}
}

func TestVerifyRejectsBadKeyAndSignatureEncoding(t *testing.T) {
	pub, priv := testKey(t)
	canon, sig, err := Sign(priv, testEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pub[:16], canon, sig); err == nil {
		t.Fatal("expected error for truncated public key")
	}
	if _, err := Verify(pub, canon, "!!!not-base64!!!"); err == nil {
		t.Fatal("expected error for non-base64 signature")
	}
}

func TestCanonicalRejectsNegativeTimestamp(t *testing.T) {
	e := testEnvelope()
	e.Timestamp = -1
	if _, err := e.Canonical(); err == nil {
		t.Fatal("expected error for negative timestamp")
	}
}

func TestParseRejectsEmptyTimestampField(t *testing.T) {
	base, err := testEnvelope().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Replace(base, "|1780000000|", "||", 1)
	if _, err := Parse(in); err == nil {
		t.Fatal("expected error for empty timestamp field")
	}
}

func TestVerdictCanonicalRejectsBadFields(t *testing.T) {
	v := testVerdict()
	v.EnvHash = "beef"
	if _, err := v.Canonical(); err == nil {
		t.Fatal("expected error for short env hash")
	}
	v = testVerdict()
	v.LastSeenUnix = -1
	if _, err := v.Canonical(); err == nil {
		t.Fatal("expected error for negative last_seen")
	}
	v = testVerdict()
	v.KeyGeneration = -2
	if _, err := v.Canonical(); err == nil {
		t.Fatal("expected error for negative key generation")
	}
	v = testVerdict()
	v.VerifiedAt = -3
	if _, err := v.Canonical(); err == nil {
		t.Fatal("expected error for negative verified_at")
	}
}

func TestSignVerdictRejectsInvalidVerdict(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := testVerdict()
	v.EnvHash = "nope"
	if _, _, err := SignVerdict(priv, v); err == nil {
		t.Fatal("expected SignVerdict to reject an invalid verdict")
	}
}

func TestParseVerdictFieldErrors(t *testing.T) {
	base, err := testVerdict().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"bad address":     strings.Replace(base, "0001abcd1234", "0001ABCD1234", 1),
		"bad last_seen":   strings.Replace(base, "|1779999980|", "|017|", 1),
		"bad keygen":      strings.Replace(base, "|3|", "|x|", 1),
		"bad verified_at": strings.Replace(base, "|1780000000", "|-1", 1),
		"bad online bool": strings.Replace(base, "|1|1|0|", "|1|yes|0|", 1),
		"bad member bool": strings.Replace(base, "|1|1|0|", "|1|1|2|", 1),
	}
	for name, in := range cases {
		if in == base {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParseVerdict(in); err == nil {
			t.Errorf("%s: expected parse error", name)
		}
	}
}

func TestVerifyVerdictWithKeyRejectsBadInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canon, sig, err := SignVerdict(priv, testVerdict())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVerdictWithKey(pub[:8], canon, sig); err == nil {
		t.Fatal("expected error for truncated verdict key")
	}
	if _, err := VerifyVerdictWithKey(pub, canon, "%%%"); err == nil {
		t.Fatal("expected error for non-base64 verdict signature")
	}
	if _, err := VerifyVerdictWithKey(pub, "garbage", sig); err == nil {
		t.Fatal("expected error for unparseable verdict")
	}
}

func TestVerdictKeyringMalformedEntries(t *testing.T) {
	saved := verdictKeyringB64
	defer func() { verdictKeyringB64 = saved }()

	verdictKeyringB64 = "no-equals-sign,vfy-bad=!!!,vfy-short=YWJj"
	for _, kid := range []string{"no-equals-sign", "vfy-bad", "vfy-short"} {
		if k := verdictKeyFor(kid); k != nil {
			t.Errorf("kid %q: expected nil key from malformed entry", kid)
		}
	}
}
