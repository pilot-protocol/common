// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

func TestRegisterWithKeyOptsCarriesProofOfPossession(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	c.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(challenge)))
	})

	const listenAddr = "1.2.3.4:4000"
	resp, err := c.RegisterWithKeyOpts(RegisterOpts{
		ListenAddr: listenAddr,
		PublicKey:  pubB64,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	sigB64, ok := echo["signature"].(string)
	if !ok || sigB64 == "" {
		t.Fatalf("register message carries no signature: %#v", echo)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature not base64: %v", err)
	}
	challenge := fmt.Sprintf("register:%s:%s", listenAddr, pubB64)
	if !ed25519.Verify(pub, []byte(challenge), sig) {
		t.Fatalf("signature does not verify against submitted public_key for %q", challenge)
	}
}

func TestRegisterWithKeyReRegistrationBindsPublicKey(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	c.SetSigner(func(challenge string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(challenge)))
	})

	const listenAddr = "x:1"
	resp, err := c.RegisterWithKey(listenAddr, pubB64, "bob", []string{"10.0.0.1:80"}, "v1.2.3")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	sigB64, _ := echo["signature"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || sigB64 == "" {
		t.Fatalf("re-registration carries no verifiable signature: %q (%v)", sigB64, err)
	}
	challenge := fmt.Sprintf("register:%s:%s", listenAddr, pubB64)
	if !ed25519.Verify(pub, []byte(challenge), sig) {
		t.Fatalf("re-registration signature does not bind submitted public_key")
	}
}

func TestRegisterWithKeyOptsNoSignerOmitsSignature(t *testing.T) {
	t.Parallel()
	srv := newFakeJSONServer(t, echoHandler())
	defer srv.close()
	c, _ := Dial(srv.addr())
	defer c.Close()

	resp, err := c.RegisterWithKeyOpts(RegisterOpts{ListenAddr: "x:1", PublicKey: "PUB=="})
	if err != nil {
		t.Fatalf("register without signer should still succeed: %v", err)
	}
	echo, _ := resp["echo"].(map[string]interface{})
	if _, ok := echo["signature"]; ok {
		t.Fatalf("signature must be omitted when no signer is configured (backward compatibility)")
	}
	if got, _ := echo["public_key"].(string); got != "PUB==" {
		t.Fatalf("public_key: %q", got)
	}
}
