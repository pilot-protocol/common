// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReceiptIsSignedBoundAndIdempotent(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	result := Decision{
		Version: SchemaVersion, ID: "decision-receipt", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Deny,
		PolicyRevision: 9, RevocationEpoch: 4, ProviderID: "managed",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	receipt, err := NewReceipt(intent, result, "daemon-node-7", "receipt-key-1", now.Unix(), Denied)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyFor(intent, result, publicKey); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	second, err := NewReceipt(intent, result, "daemon-node-7", "receipt-key-1", now.Add(time.Second).Unix(), Denied)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.UsageUnitID() != second.UsageUnitID() {
		t.Fatal("retry generated a second billable usage identifier")
	}
	tampered := receipt
	tampered.Result = Enforced
	if err := tampered.Verify(publicKey); err == nil {
		t.Fatalf("tampered receipt error = %v", err)
	}
}

func TestReceiptRejectsNonCanonicalIDAndCrossDecisionReplay(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	result := Decision{
		Version: SchemaVersion, ID: "decision-a", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Allow,
		ProviderID: "local", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	receipt, err := NewReceipt(intent, result, "wallet-1", "receipt-key", now.Unix(), Enforced)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	badID := receipt
	badID.ID = strings.Repeat("a", 64)
	if err := badID.Validate(); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical receipt id error = %v", err)
	}
	other := result
	other.ID = "decision-b"
	if err := receipt.VerifyFor(intent, other, publicKey); err == nil {
		t.Fatal("receipt replayed across decisions")
	}
}

func TestReceiptCanBeAttributedToASeparateEnforcementAgent(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	result := Decision{
		Version: SchemaVersion, ID: "decision-receiver-receipt", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Allow,
		ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	receipt, err := NewReceiptForEnforcer(intent, result, "receiver-a", "dataexchange", "receiver-receipt-key", now.Unix(), Enforced)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.AgentID != "receiver-a" {
		t.Fatalf("receipt enforcement agent = %q", receipt.AgentID)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyForEnforcer(intent, result, "receiver-a", publicKey); err != nil {
		t.Fatalf("receiver receipt rejected: %v", err)
	}
	if err := receipt.VerifyFor(intent, result, publicKey); err == nil {
		t.Fatal("receiver receipt verified as if it were signed by the sender")
	}
}

func TestDisclosureReceiptV2BindsCanonicalDisclosureWithoutChangingV1(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	disclosure := DisclosureBinding{
		Version: DisclosureBindingVersion, ContentHash: HashPayload([]byte("invoice")), DeclaredBytes: 7,
		ContentType: "application/pdf", Labels: []string{"finance", "pii"}, Recipient: "agent:finance",
		Purpose: "invoice-payment", Residency: "eu-west-1", Filename: "invoice.pdf",
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(t, now)
	intent.Audience, intent.Purpose, intent.PayloadHash = disclosure.Recipient, disclosure.Purpose, disclosureHash
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := Decision{
		Version: SchemaVersion, ID: "decision-disclosure-receipt", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: Allow, PolicyRevision: 9, RevocationEpoch: 4, ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	receipt, err := NewDisclosureReceiptForEnforcer(intent, result, disclosure, "receiver-a", "dataexchange", "receipt-key", now.Unix(), Enforced)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Version != ReceiptDisclosureVersion || receipt.DisclosureHash != disclosureHash {
		t.Fatalf("receipt=%+v", receipt)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyForDisclosure(intent, result, disclosure, "receiver-a", publicKey); err != nil {
		t.Fatalf("V2 disclosure receipt rejected: %v", err)
	}
	mutated := disclosure
	mutated.Residency = "us-east-1"
	if err := receipt.VerifyForDisclosure(intent, result, mutated, "receiver-a", publicKey); err == nil {
		t.Fatal("receipt verified for a mutated disclosure")
	}
	v1 := receipt
	v1.Version, v1.DisclosureHash = SchemaVersion, ""
	if err := v1.Validate(); err != nil {
		t.Fatalf("converted V1 fields invalid: %v", err)
	}
	if err := v1.Verify(publicKey); err == nil {
		t.Fatal("V2 signature was accepted with V1 canonical bytes")
	}
}

func FuzzReceiptCanonicalization(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"id":"0000000000000000000000000000000000000000000000000000000000000000","decision_id":"decision-a","decision_hash":"0000000000000000000000000000000000000000000000000000000000000000","intent_hash":"0000000000000000000000000000000000000000000000000000000000000000","tenant_id":"tenant-a","agent_id":"agent-a","outcome":"deny","result":"denied","enforcement_point":"wallet","observed_at":1,"key_id":"receipt-a"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var receipt Receipt
		if err := decoder.Decode(&receipt); err != nil {
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			return
		}
		if err := receipt.Validate(); err != nil {
			return
		}
		canonical, err := receipt.Canonical()
		if err != nil || len(canonical) == 0 {
			t.Fatalf("valid receipt canonicalization failed: bytes=%d err=%v", len(canonical), err)
		}
		if _, err := receipt.Hash(); err != nil {
			t.Fatalf("valid receipt hash failed: %v", err)
		}
	})
}
