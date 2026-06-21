// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"encoding/json"
	"testing"
)

// TestDriverClose covers the trivial Close() forwarder.
func TestDriverClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := drv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestDriverBroadcast covers the happy-path Broadcast (network + port +
// admin token + data → cmdBroadcastOK).
func TestDriverBroadcast(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdBroadcast, func(frame []byte) [][]byte {
		return [][]byte{{cmdBroadcastOK}}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	if err := drv.Broadcast(1, 8080, []byte("hello"), "admin-token"); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
}

// TestConnClose covers Conn.Close (cmdClose fire-and-forget) and its
// idempotency — second Close is a no-op.
func TestConnClose(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	// Dial to get a Conn back.
	d.onCmd(cmdDial, func(frame []byte) [][]byte {
		resp := make([]byte, 5)
		resp[0] = cmdDialOK
		resp[1] = 0x00
		resp[2] = 0x00
		resp[3] = 0x00
		resp[4] = 0x42
		return [][]byte{resp}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	conn, err := drv.Dial("0:0000.0000.0001:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Second Close is idempotent.
	if err := conn.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestDriverWaitForTrust covers the handshake-wait JSON-RPC.
func TestDriverWaitForTrust(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdHandshake, func(frame []byte) [][]byte {
		// Verify the sub-command byte (0x07 = subHandshakeWait).
		if len(frame) < 2 || frame[1] != subHandshakeWait {
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		body := []byte(`{"trusted":true}`)
		return [][]byte{append([]byte{cmdHandshakeOK}, body...)}
	})

	drv, _ := Connect(d.path)
	defer drv.Close()

	result, err := drv.WaitForTrust(0xCAFE, 5000)
	if err != nil {
		t.Fatalf("WaitForTrust: %v", err)
	}
	if result == nil {
		t.Errorf("result is nil")
	}
}

// TestDriverPreferDirect covers PreferDirect's JSON-RPC roundtrip:
//   - the request frame is exactly [cmdPreferDirect(0x2D)][big-endian uint32 nodeID] (5 bytes),
//   - the cmdPreferDirectOK (0x2E) reply is routed/accepted by readLoop (not dropped) —
//     proven by the happy path returning a non-nil result and nil error, which only
//     happens if the OK frame reaches the in-flight sendAndWait via c.pending,
//   - the daemon's returned routing state is unmarshalled and surfaced.
func TestDriverPreferDirect(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	const nodeID uint32 = 0xDEADBEEF

	d.onCmd(cmdPreferDirect, func(frame []byte) [][]byte {
		// Frame is [cmd][payload]; assert the exact 5-byte wire shape.
		if len(frame) != 5 {
			t.Errorf("PreferDirect frame len = %d, want 5", len(frame))
			return [][]byte{{cmdError, 0, 0, 'l', 'e', 'n'}}
		}
		if frame[0] != cmdPreferDirect {
			t.Errorf("PreferDirect opcode = 0x%02X, want 0x%02X", frame[0], cmdPreferDirect)
		}
		if got := binary.BigEndian.Uint32(frame[1:5]); got != nodeID {
			t.Errorf("PreferDirect nodeID = 0x%08X, want 0x%08X", got, nodeID)
		}
		body := []byte(`{"node_id":3735928559,"relay_active":false,"pinned":false,"real_addr":"1.2.3.4:9000"}`)
		return [][]byte{append([]byte{cmdPreferDirectOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.PreferDirect(nodeID)
	if err != nil {
		t.Fatalf("PreferDirect: %v", err)
	}
	if result == nil {
		t.Fatalf("PreferDirect result is nil")
	}
	// The cmdPreferDirectOK payload must have been routed (not dropped) and
	// unmarshalled — check a field round-tripped.
	if ra, ok := result["relay_active"].(bool); !ok || ra {
		t.Errorf("relay_active = %v (ok=%v), want false", result["relay_active"], ok)
	}
}

// TestDriverRotateKey covers RotateKey's JSON-RPC roundtrip.
func TestDriverRotateKey(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdRotateKey, func(frame []byte) [][]byte {
		// jsonRPC expects [cmdRotateKeyOK][JSON body]
		body := []byte(`{"old_node_id":1,"new_node_id":2}`)
		resp := append([]byte{cmdRotateKeyOK}, body...)
		return [][]byte{resp}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if result == nil {
		t.Errorf("RotateKey result is nil")
	}
}

// TestDriverSubmitBadge covers SubmitBadge's JSON-RPC roundtrip: the request
// frame is [cmdSubmitBadge][JSON{badge,badge_sig}] and the cmdSubmitBadgeOK
// reply is routed and unmarshalled. A new response opcode that readLoop does
// not allowlist would silently hang here — this pins that wiring.
func TestDriverSubmitBadge(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	const wantBadge = "pilotbadge:v1:109517:github:1781827200:0:bdg-v1:"
	const wantSig = "ZmFrZS1zaWc="

	d.onCmd(cmdSubmitBadge, func(frame []byte) [][]byte {
		if frame[0] != cmdSubmitBadge {
			t.Errorf("opcode = 0x%02X, want 0x%02X", frame[0], cmdSubmitBadge)
		}
		var got map[string]string
		if err := json.Unmarshal(frame[1:], &got); err != nil {
			t.Errorf("payload not JSON: %v", err)
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		if got["badge"] != wantBadge || got["badge_sig"] != wantSig {
			t.Errorf("payload = %+v, want badge=%q sig=%q", got, wantBadge, wantSig)
		}
		body := []byte(`{"ok":true}`)
		return [][]byte{append([]byte{cmdSubmitBadgeOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.SubmitBadge(wantBadge, wantSig)
	if err != nil {
		t.Fatalf("SubmitBadge: %v", err)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("result = %+v, want ok=true", result)
	}
}

// TestDriverEnrollRecovery covers EnrollRecovery's JSON-RPC roundtrip.
func TestDriverEnrollRecovery(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	const wantEnroll = "pilotenroll:v1:109517:github:Y29tbWl0:1781827200:bdg-v1"
	const wantSig = "ZW5yb2xsLXNpZw=="

	d.onCmd(cmdEnrollRecovery, func(frame []byte) [][]byte {
		var got map[string]string
		if err := json.Unmarshal(frame[1:], &got); err != nil {
			t.Errorf("payload not JSON: %v", err)
			return [][]byte{{cmdError, 'b', 'a', 'd'}}
		}
		if got["enrollment"] != wantEnroll || got["enrollment_sig"] != wantSig {
			t.Errorf("payload = %+v, want enrollment=%q sig=%q", got, wantEnroll, wantSig)
		}
		body := []byte(`{"ok":true}`)
		return [][]byte{append([]byte{cmdEnrollRecoveryOK}, body...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	result, err := drv.EnrollRecovery(wantEnroll, wantSig)
	if err != nil {
		t.Fatalf("EnrollRecovery: %v", err)
	}
	if ok, _ := result["ok"].(bool); !ok {
		t.Errorf("result = %+v, want ok=true", result)
	}
}
