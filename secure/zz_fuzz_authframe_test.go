// SPDX-License-Identifier: AGPL-3.0-or-later

package secure_test

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"

	"github.com/pilot-protocol/common/secure"
)

// VerifyAuthFrame consumes the peer's auth frame after the ECDH exchange.
// The frame bytes are remote-controlled, and peerEdPubKey comes from a
// registry lookup or a caller-supplied HandshakeConfig — neither is
// guaranteed to be a well-formed Ed25519 key, and ed25519.Verify panics on
// a key that is not exactly PublicKeySize bytes.
func FuzzVerifyAuthFrame(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add(make([]byte, secure.AuthFrameLen), 0)
	f.Add(make([]byte, secure.AuthFrameLen-1), 0)
	f.Add(make([]byte, secure.AuthFrameLen+1), 0)
	// Same frame against every malformed key length in the table below.
	for i := 0; i < 6; i++ {
		f.Add(make([]byte, secure.AuthFrameLen), i)
	}
	// A frame carrying a plausible (in-window) timestamp so the fuzzer gets
	// past the skew gate and reaches the signature verify.
	{
		b := make([]byte, secure.AuthFrameLen)
		binary.BigEndian.PutUint32(b[0:4], 1234)
		binary.BigEndian.PutUint64(b[4:12], uint64(time.Now().Unix()))
		f.Add(b, 0)
		f.Add(b, 1)
	}

	realPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}
	// Index 0 is the only well-formed key; the rest are the shapes that
	// reach ed25519.Verify from a corrupt or partially-populated record.
	keys := []ed25519.PublicKey{
		realPub,
		nil,
		{},
		make([]byte, 1),
		make([]byte, ed25519.PublicKeySize-1),
		make([]byte, ed25519.PublicKeySize+1),
	}

	peerX25519 := make([]byte, 32)
	var nonceSeq uint64

	f.Fuzz(func(t *testing.T, frame []byte, keyIdx int) {
		if len(frame) > 4096 {
			frame = frame[:4096]
		}
		if keyIdx < 0 {
			keyIdx = -keyIdx
		}
		key := keys[keyIdx%len(keys)]

		// Run the frame as-is first: that covers the length guard and the
		// timestamp-skew rejection.
		if _, err := secure.VerifyAuthFrame(frame, key, peerX25519, time.Now()); err == nil {
			t.Fatalf("VerifyAuthFrame accepted an unsigned frame (len=%d, keyLen=%d)", len(frame), len(key))
		}

		// Then run a normalised copy. Without this, almost every input dies
		// at the timestamp gate or (for a repeated nonce) at the replay
		// gate, and the Ed25519 verify — the part that is sensitive to key
		// length — is never reached. A real peer always presents a fresh
		// timestamp and nonce, so this is the shape that matters.
		if len(frame) == secure.AuthFrameLen {
			fresh := make([]byte, secure.AuthFrameLen)
			copy(fresh, frame)
			binary.BigEndian.PutUint64(fresh[4:12], uint64(time.Now().Unix()))
			nonceSeq++
			binary.BigEndian.PutUint64(fresh[12:20], nonceSeq)
			binary.BigEndian.PutUint64(fresh[20:28], uint64(keyIdx))
			if _, err := secure.VerifyAuthFrame(fresh, key, peerX25519, time.Now()); err == nil {
				t.Fatalf("VerifyAuthFrame accepted an unsigned fresh frame (keyLen=%d)", len(key))
			}
		}
	})
}
