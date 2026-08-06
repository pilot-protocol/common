// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestEvaluatorAttestationBindsEndpointResidencyAndIndependentKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0).UTC()
	attestation := EvaluatorAttestation{
		Version: EvaluatorAttestationVersion, Endpoint: "https://evaluator.example/v1/authorize", Residency: "eu-west-1",
		AttestorID: "regional-attestor", EvidenceHash: strings.Repeat("a", 64), IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), KeyID: "region-key-1",
	}
	if err := attestation.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := attestation.VerifyForEndpoint("https://evaluator.example/v1/authorize", "eu-west-1", "regional-attestor", "region-key-1", publicKey, now); err != nil {
		t.Fatal(err)
	}
	if err := attestation.VerifyForEndpoint("https://other.example", "eu-west-1", "regional-attestor", "region-key-1", publicKey, now); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("endpoint mismatch error=%v", err)
	}
	if err := attestation.VerifyForEndpoint("https://evaluator.example", "us-east-1", "regional-attestor", "region-key-1", publicKey, now); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("residency mismatch error=%v", err)
	}
	attestation.Signature = "bad"
	if err := attestation.VerifyForEndpoint("https://evaluator.example", "eu-west-1", "regional-attestor", "region-key-1", publicKey, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("signature mismatch error=%v", err)
	}
}
