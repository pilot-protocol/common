package driver

import (
	"strings"
	"testing"
)

// The input bounds reject garbage client-side, before any daemon round trip,
// so a nil driver is safe: reaching jsonRPC would panic and fail the test.
func TestSignEnvelopeInputBounds(t *testing.T) {
	var d *Driver
	hash := strings.Repeat("ab", 32)

	if _, err := d.SignEnvelope("svc", "beef"); err == nil {
		t.Fatal("expected error for short body hash")
	}
	if _, err := d.SignEnvelope("svc", ""); err == nil {
		t.Fatal("expected error for empty body hash")
	}
	if _, err := d.SignEnvelope("", hash); err == nil {
		t.Fatal("expected error for empty audience")
	}
	if _, err := d.SignEnvelope(strings.Repeat("a", 65), hash); err == nil {
		t.Fatal("expected error for oversized audience")
	}
}

func TestVerifyEnvelopeInputBounds(t *testing.T) {
	var d *Driver

	if _, err := d.VerifyEnvelope("", "c2ln", false); err == nil {
		t.Fatal("expected error for empty envelope")
	}
	if _, err := d.VerifyEnvelope(strings.Repeat("x", maxEnvelopeLen+1), "c2ln", false); err == nil {
		t.Fatal("expected error for oversized envelope")
	}
	if _, err := d.VerifyEnvelope("pilot-req-v1|x", "", false); err == nil {
		t.Fatal("expected error for empty signature")
	}
	if _, err := d.VerifyEnvelope("pilot-req-v1|x", strings.Repeat("A", maxSigB64Len+1), false); err == nil {
		t.Fatal("expected error for oversized signature")
	}
}
