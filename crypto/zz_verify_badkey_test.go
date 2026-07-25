// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestVerifyRejectsWrongLengthKeyWithoutPanic(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("challenge")
	sig := id.Sign(msg)

	for _, n := range []int{0, 1, 5, 31, 33, 64} {
		bad := make([]byte, n)
		if Verify(bad, msg, sig) {
			t.Fatalf("Verify accepted a %d-byte public key", n)
		}
	}

	if Verify(nil, msg, sig) {
		t.Fatal("Verify accepted a nil public key")
	}

	if !Verify(id.PublicKey, msg, sig) {
		t.Fatal("Verify rejected a valid signature")
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("unexpected key size %d", len(id.PublicKey))
	}
}
