// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/json"
	"testing"
)

// TestDriverSignEnvelope covers SignEnvelope's JSON-RPC roundtrip: the
// request frame is [cmdSignEnvelope][JSON{audience,body_hash}] and the
// cmdSignEnvelopeOK reply is routed by readLoop's allowlist and
// unmarshalled — a new response opcode readLoop doesn't allowlist would
// silently hang here.
func TestDriverSignEnvelope(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	const wantAudience = "svc.example.io"
	const wantHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	d.onCmd(cmdSignEnvelope, func(frame []byte) [][]byte {
		if frame[0] != cmdSignEnvelope {
			t.Errorf("opcode = 0x%02X, want 0x%02X", frame[0], cmdSignEnvelope)
		}
		var got map[string]string
		if err := json.Unmarshal(frame[1:], &got); err != nil {
			t.Errorf("payload not JSON: %v", err)
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		if got["audience"] != wantAudience || got["body_hash"] != wantHash {
			t.Errorf("payload = %+v, want audience=%q body_hash=%q", got, wantAudience, wantHash)
		}
		body := []byte(`{"type":"sign_envelope_ok","envelope":"pilot-req-v1|...","signature":"c2ln","address":"0:0000.0000.0007"}`)
		return [][]byte{append([]byte{cmdSignEnvelopeOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.SignEnvelope(wantAudience, wantHash)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if sig, _ := result["signature"].(string); sig != "c2ln" {
		t.Errorf("result = %+v, want signature=c2ln", result)
	}
	if addr, _ := result["address"].(string); addr != "0:0000.0000.0007" {
		t.Errorf("address = %v", result["address"])
	}
}

// TestDriverSignEnvelopeEmptyBodyHash pins the client-side guard: an empty
// body hash is refused before any IPC frame goes out.
func TestDriverSignEnvelopeEmptyBodyHash(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	if _, err := drv.SignEnvelope("svc.example.io", ""); err == nil {
		t.Fatal("SignEnvelope with empty body hash should fail")
	}
}

// TestDriverVerifyEnvelope covers VerifyEnvelope's JSON-RPC roundtrip and the
// wire shape of the optional fields (check_standing, max_skew_secs default 0).
func TestDriverVerifyEnvelope(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	const wantEnvelope = "pilot-req-v1|000000000007|1|00112233aabbccdd|hash|svc.example.io"
	const wantSig = "c2ln"

	d.onCmd(cmdVerifyEnvelope, func(frame []byte) [][]byte {
		var got map[string]interface{}
		if err := json.Unmarshal(frame[1:], &got); err != nil {
			t.Errorf("payload not JSON: %v", err)
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		if got["envelope"] != wantEnvelope || got["signature"] != wantSig {
			t.Errorf("payload = %+v", got)
		}
		if cs, _ := got["check_standing"].(bool); cs {
			t.Errorf("check_standing = %v, want false", got["check_standing"])
		}
		if skew, _ := got["max_skew_secs"].(float64); skew != 0 {
			t.Errorf("max_skew_secs = %v, want 0 (daemon default)", got["max_skew_secs"])
		}
		body := []byte(`{"type":"verify_envelope_ok","valid":true,"node_id":7,"verified_via":"cache","trusted":false}`)
		return [][]byte{append([]byte{cmdVerifyEnvelopeOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.VerifyEnvelope(wantEnvelope, wantSig, false)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if valid, _ := result["valid"].(bool); !valid {
		t.Errorf("result = %+v, want valid=true", result)
	}
	if via, _ := result["verified_via"].(string); via != "cache" {
		t.Errorf("verified_via = %v", result["verified_via"])
	}
}

// TestDriverVerifyEnvelopeMaxSkewAndStanding covers the explicit-skew variant
// and standing passthrough.
func TestDriverVerifyEnvelopeMaxSkewAndStanding(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdVerifyEnvelope, func(frame []byte) [][]byte {
		var got map[string]interface{}
		if err := json.Unmarshal(frame[1:], &got); err != nil {
			t.Errorf("payload not JSON: %v", err)
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		if cs, _ := got["check_standing"].(bool); !cs {
			t.Errorf("check_standing = %v, want true", got["check_standing"])
		}
		if skew, _ := got["max_skew_secs"].(float64); skew != 600 {
			t.Errorf("max_skew_secs = %v, want 600", got["max_skew_secs"])
		}
		body := []byte(`{"type":"verify_envelope_ok","valid":false,"reason":"reqsig: envelope timestamp outside window"}`)
		return [][]byte{append([]byte{cmdVerifyEnvelopeOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.VerifyEnvelopeMaxSkew("env", "sig", true, 600)
	if err != nil {
		t.Fatalf("VerifyEnvelopeMaxSkew: %v", err)
	}
	// A failed check is a verdict, not an error.
	if valid, _ := result["valid"].(bool); valid {
		t.Errorf("result = %+v, want valid=false", result)
	}
	if reason, _ := result["reason"].(string); reason == "" {
		t.Errorf("reason missing: %+v", result)
	}
}
