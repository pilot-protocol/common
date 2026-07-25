// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"encoding/binary"
	"testing"

	"github.com/pilot-protocol/common/registry/wire"
)

// The sibling zz_fuzz_wire_test.go covers the framing layer and the
// client-side *response* decoders. These targets cover the three
// server-side *request* decoders, which are the ones fed directly from an
// unauthenticated TCP peer by accept.handleBinaryConn — the registry
// serves the whole fleet, so a panic here is a fleet-wide outage.

func FuzzDecodeHeartbeatReqBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 67))
	f.Add(make([]byte, 68))
	f.Add(make([]byte, 69))
	f.Add(make([]byte, 4096))
	{
		b := make([]byte, 68)
		binary.BigEndian.PutUint32(b[:4], 0xFFFFFFFF)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		req, err := wire.DecodeHeartbeatReq(payload)
		if err != nil {
			return
		}
		if len(payload) < 68 {
			t.Fatalf("accepted a %d-byte heartbeat request", len(payload))
		}
		// The decoded signature is handed straight to the verifier; it must
		// always be exactly SignatureSize.
		if len(req.Signature) != 64 {
			t.Fatalf("decoded signature is %d bytes, want 64", len(req.Signature))
		}
	})
}

func FuzzDecodeLookupReqBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 3))
	f.Add(make([]byte, 4))
	f.Add(make([]byte, 5))
	f.Add(make([]byte, 65535))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if _, err := wire.DecodeLookupReq(payload); err != nil {
			return
		}
		if len(payload) < 4 {
			t.Fatalf("accepted a %d-byte lookup request", len(payload))
		}
	})
}

func FuzzDecodeResolveReqBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 71))
	f.Add(make([]byte, 72))
	f.Add(make([]byte, 73))
	f.Add(make([]byte, 8192))
	{
		b := make([]byte, 72)
		binary.BigEndian.PutUint32(b[0:4], 1)
		binary.BigEndian.PutUint32(b[4:8], 2)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _, sig, err := wire.DecodeResolveReq(payload)
		if err != nil {
			return
		}
		if len(payload) < 72 {
			t.Fatalf("accepted a %d-byte resolve request", len(payload))
		}
		// sig is passed to the signature verifier without further length
		// handling, so the decoder owns this invariant.
		if len(sig) != 64 {
			t.Fatalf("decoded signature is %d bytes, want 64", len(sig))
		}
	})
}

// FuzzDecodeErrorBounds covers the error-payload decoder, which trusts a
// wire-supplied uint16 length to slice its own buffer.
func FuzzDecodeErrorBounds(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0xFF, 0xFF, 'a', 'b'})
	f.Add([]byte{0x00, 0x04, 'a'})
	f.Add(wire.EncodeError("boom"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = wire.DecodeError(payload)
	})
}
