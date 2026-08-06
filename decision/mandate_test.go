// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type mandateStoreStub struct {
	mandate Mandate
	err     error
}

func (store mandateStoreStub) Mandate(context.Context, string, string) (Mandate, error) {
	return store.mandate, store.err
}

type mandateKeyStub struct {
	key             ed25519.PublicKey
	revocationEpoch uint64
}

func (trust mandateKeyStub) MandateKey(context.Context, string, string) (ed25519.PublicKey, error) {
	return trust.key, nil
}

func (trust mandateKeyStub) MinimumState(context.Context, string) (uint64, uint64, error) {
	return 1, trust.revocationEpoch, nil
}

func delegatedMandateFixture(t *testing.T) (Mandate, Intent, Decision, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	mandate := Mandate{
		Version: SchemaVersion, ID: "mandate-finance-1", TenantID: "tenant-acme", SubjectAgentID: "agent-buyer-1",
		Actions: []string{"wallet.pay"}, ResourcePrefixes: []string{"merchant:approved/"}, Audience: "agent:vendor-a", Purpose: "invoice-42",
		Constraints: []Constraint{{Key: "amount_usdc", Operator: "max", Value: "100"}}, RevocationEpoch: 3,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), KeyID: "mandate-key-1",
	}
	if err := mandate.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	intent := Intent{
		Version: SchemaVersion, ID: "intent-mandate-1", TenantID: mandate.TenantID, AgentID: mandate.SubjectAgentID,
		Action: "wallet.pay", Resource: "merchant:approved/vendor-a", MandateID: mandate.ID, Audience: mandate.Audience, Purpose: mandate.Purpose,
		PayloadHash: HashPayload([]byte(`{"amount":"25"}`)), Risk: RiskHigh, IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "agent-key-1",
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := Decision{
		Version: SchemaVersion, ID: "decision-mandate-1", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: Constrain, Constraints: append([]Constraint(nil), mandate.Constraints...), PolicyRevision: 1, RevocationEpoch: mandate.RevocationEpoch,
		ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "decision-key-1",
	}
	return mandate, intent, result, publicKey, privateKey, now
}

func TestMandateCanonicalSignatureAndScope(t *testing.T) {
	mandate, intent, result, publicKey, _, now := delegatedMandateFixture(t)
	if err := mandate.Verify(publicKey, now); err != nil {
		t.Fatalf("verify mandate: %v", err)
	}
	if err := mandate.Check(intent, result); err != nil {
		t.Fatalf("check mandate: %v", err)
	}
	tampered := mandate
	tampered.Purpose = "other-invoice"
	if err := tampered.Verify(publicKey, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered mandate error=%v", err)
	}
	wrongAudience := intent
	wrongAudience.Audience = "agent:vendor-b"
	if err := mandate.Check(wrongAudience, result); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("audience error=%v", err)
	}
	missingConstraint := result
	missingConstraint.Constraints = nil
	missingConstraint.Outcome = Allow
	if err := mandate.Check(intent, missingConstraint); err == nil || !strings.Contains(err.Error(), "constraints") {
		t.Fatalf("constraint error=%v", err)
	}
}

func TestMandateCeilingFailsClosedOnMissingOrStaleMandate(t *testing.T) {
	mandate, intent, result, publicKey, _, now := delegatedMandateFixture(t)
	ceiling := MandateCeiling{
		Store: mandateStoreStub{mandate: mandate}, Keys: mandateKeyStub{key: publicKey, revocationEpoch: 3},
		Next: ceilingFunc(func(context.Context, Intent, Decision) error { return nil }), Now: func() time.Time { return now },
	}
	if err := ceiling.Check(context.Background(), intent, result); err != nil {
		t.Fatalf("valid mandate ceiling rejected: %v", err)
	}
	missing := intent
	missing.MandateID = ""
	if err := ceiling.Check(context.Background(), missing, result); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing mandate error=%v", err)
	}
	stale := MandateCeiling{
		Store: mandateStoreStub{mandate: mandate}, Keys: mandateKeyStub{key: publicKey, revocationEpoch: 4},
		Now: func() time.Time { return now },
	}
	if err := stale.Check(context.Background(), intent, result); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale mandate error=%v", err)
	}
}

func TestDelegatedIntentAndReceiptCannotBeReplayedAsUnmandated(t *testing.T) {
	mandate, intent, result, _, privateKey, now := delegatedMandateFixture(t)
	if err := intent.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	copyIntent := intent
	copyIntent.MandateID = ""
	if err := copyIntent.Verify(privateKey.Public().(ed25519.PublicKey), now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("unmandated replay error=%v", err)
	}
	receipt, err := NewReceipt(intent, result, "wallet", "receipt-key", now.Unix(), Enforced)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.MandateID != mandate.ID {
		t.Fatalf("receipt mandate=%q, want %q", receipt.MandateID, mandate.ID)
	}
	if err := receipt.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := receipt.VerifyFor(intent, result, privateKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("delegated receipt rejected: %v", err)
	}
	unmandated := intent
	unmandated.MandateID = ""
	if err := receipt.VerifyFor(unmandated, result, privateKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("receipt replayed to unmandated intent")
	}
}

func TestStaticMandateStoreVerifiesSnapshotAndReturnsIndependentCopies(t *testing.T) {
	mandate, _, _, publicKey, _, now := delegatedMandateFixture(t)
	store, err := NewStaticMandateStore(context.Background(), mandate.TenantID, []Mandate{mandate}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch}, now)
	if err != nil {
		t.Fatalf("new mandate store: %v", err)
	}
	first, err := store.Mandate(context.Background(), mandate.TenantID, mandate.ID)
	if err != nil {
		t.Fatalf("read mandate: %v", err)
	}
	first.Actions[0] = "tampered"
	second, err := store.Mandate(context.Background(), mandate.TenantID, mandate.ID)
	if err != nil || second.Actions[0] != "wallet.pay" {
		t.Fatalf("mandate snapshot mutated: %+v, err=%v", second, err)
	}
	if _, err := NewStaticMandateStore(context.Background(), mandate.TenantID, []Mandate{mandate, mandate}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch}, now); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate mandate error=%v", err)
	}
	if _, err := NewStaticMandateStore(context.Background(), mandate.TenantID, []Mandate{mandate}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch + 1}, mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch + 1}, now); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("stale mandate snapshot error=%v", err)
	}
}

func TestMandateBundleBindsRevisionAndSupportsFailClosedRemoval(t *testing.T) {
	mandate, _, _, publicKey, privateKey, now := delegatedMandateFixture(t)
	bundle := MandateBundle{
		Version: SchemaVersion, TenantID: mandate.TenantID, SubjectAgentID: mandate.SubjectAgentID,
		Revision: 7, RevocationEpoch: mandate.RevocationEpoch, Mandates: []Mandate{mandate},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), KeyID: mandate.KeyID,
	}
	if err := bundle.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	keys := mandateKeyStub{key: publicKey, revocationEpoch: mandate.RevocationEpoch}
	if err := bundle.Verify(context.Background(), publicKey, keys, now); err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	store, err := NewStaticMandateStoreFromBundle(context.Background(), bundle, keys, keys, now)
	if err != nil {
		t.Fatalf("bundle store: %v", err)
	}
	if _, err := store.Mandate(context.Background(), mandate.TenantID, mandate.ID); err != nil {
		t.Fatalf("bundled mandate not available: %v", err)
	}
	tampered := bundle
	tampered.Mandates = append([]Mandate(nil), bundle.Mandates...)
	tampered.Mandates[0].Purpose = "tampered-purpose"
	if err := tampered.Verify(context.Background(), publicKey, keys, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered bundle error=%v", err)
	}

	removal := MandateBundle{
		Version: SchemaVersion, TenantID: mandate.TenantID, SubjectAgentID: mandate.SubjectAgentID,
		Revision: 8, RevocationEpoch: mandate.RevocationEpoch, IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), KeyID: mandate.KeyID,
	}
	if err := removal.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	removed, err := NewStaticMandateStoreFromBundle(context.Background(), removal, keys, keys, now)
	if err != nil {
		t.Fatalf("empty removal bundle: %v", err)
	}
	if _, err := removed.Mandate(context.Background(), mandate.TenantID, mandate.ID); err == nil {
		t.Fatal("removed mandate remained available")
	}
}

func FuzzMandateBundleCanonicalization(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"tenant_id":"tenant-a","subject_agent_id":"agent-a","revision":1,"revocation_epoch":1,"issued_at":1,"expires_at":2,"key_id":"issuer-a"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var bundle MandateBundle
		if err := decoder.Decode(&bundle); err != nil {
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err == nil {
			return
		}
		if err := bundle.Validate(); err != nil {
			return
		}
		canonical, err := bundle.Canonical()
		if err != nil || len(canonical) == 0 {
			t.Fatalf("valid bundle canonicalization failed: bytes=%d err=%v", len(canonical), err)
		}
		if _, err := bundle.Hash(); err != nil {
			t.Fatalf("valid bundle hash failed: %v", err)
		}
	})
}
