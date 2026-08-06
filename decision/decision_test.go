// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestValidityWindowRejectsOverflowSizedTTL(t *testing.T) {
	intent := testIntent(t, time.Unix(1785500000, 0))
	intent.IssuedAt = 1
	intent.ExpiresAt = int64(^uint64(0) >> 1)
	if err := intent.Validate(); err == nil {
		t.Fatal("overflow-sized intent TTL was accepted")
	}
}

func TestConformanceVectorV1(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	intent := Intent{
		Version: SchemaVersion, ID: "intent-vector-1", TenantID: "tenant-example", AgentID: "agent-7",
		Action: "message.send", Resource: "agent/9", PayloadHash: HashPayload([]byte("hello")),
		Risk: RiskMedium, IssuedAt: 1785500000, ExpiresAt: 1785500120,
		Nonce: "000102030405060708090a0b0c0d0e0f", KeyID: "agent-key-1",
	}
	if err := intent.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	intentCanonical, _ := intent.Canonical()
	intentHash, _ := intent.Hash()
	decision := Decision{
		Version: SchemaVersion, ID: "decision-vector-1", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Constrain,
		Reasons:        []string{"recipient policy"},
		Constraints:    []Constraint{{Key: "bytes", Operator: "max", Value: "4096"}},
		PolicyRevision: 12, RevocationEpoch: 3, ProviderID: "local-example",
		IssuedAt: 1785500001, ExpiresAt: 1785500060, KeyID: "decision-key-1",
	}
	if err := decision.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	decisionCanonical, _ := decision.Canonical()
	vectors := map[string][2]string{
		"intent canonical": {
			hex.EncodeToString(intentCanonical),
			"0000000f70696c6f742d696e74656e742d763100010000000f696e74656e742d766563746f722d310000000e74656e616e742d6578616d706c65000000076167656e742d370000000c6d6573736167652e73656e64000000076167656e742f390000004032636632346462613566623061333065323665383362326163356239653239653162313631653563316661373432356537333034333336323933386239383234000000066d656469756d000000006a6c9160000000006a6c91d80000002030303031303230333034303530363037303830393061306230633064306530660000000b6167656e742d6b65792d31",
		},
		"intent hash":      {intentHash, "66409791c5dcfe0ccada980a9140f62207539af15b3c8040a7c585fe1907f089"},
		"intent signature": {intent.Signature, "9oDEwdc6CIEQu45oGHa2zXk9H5G5ssAHI5xp1nqcvjX8+XR7G+R2MIBFKfECGt+xY/nuLCbFUFWbNF1iKZsaCA=="},
		"decision canonical": {
			hex.EncodeToString(decisionCanonical),
			"0000001170696c6f742d6465636973696f6e2d76310001000000116465636973696f6e2d766563746f722d3100000040363634303937393163356463666530636361646139383061393134306636323230373533396166313562336338303430613763353835666531393037663038390000000e74656e616e742d6578616d706c65000000076167656e742d3700000009636f6e73747261696e000100000010726563697069656e7420706f6c6963790001000000056279746573000000036d61780000000434303936000000000000000c00000000000000030000000d6c6f63616c2d6578616d706c65000000006a6c9161000000006a6c919c0000000e6465636973696f6e2d6b65792d31",
		},
		"decision signature": {decision.Signature, "uVz8UkyZDi3KtYHZoE15fpqXOXNz+cfdu3hWAIMTqev6LJ4cChZA58HzlU0riYqOokAyxZGq9pkSoYqAfSnSDQ=="},
	}
	for name, vector := range vectors {
		if vector[0] != vector[1] {
			t.Errorf("%s = %q, want %q", name, vector[0], vector[1])
		}
	}
}

func testIntent(t *testing.T, now time.Time) Intent {
	t.Helper()
	nonce, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return Intent{
		Version:     SchemaVersion,
		ID:          "intent-001",
		TenantID:    "tenant-acme",
		AgentID:     "agent-buyer-1",
		Action:      "wallet.pay",
		Resource:    "invoice/inv-42",
		PayloadHash: HashPayload([]byte(`{"amount":"25.00","asset":"USDC"}`)),
		Risk:        RiskHigh,
		IssuedAt:    now.Unix(),
		ExpiresAt:   now.Add(2 * time.Minute).Unix(),
		Nonce:       nonce,
		KeyID:       "agent-key-7",
	}
}

func TestSignedIntentRejectsTamperAndExpiry(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	if err := intent.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := intent.Verify(publicKey, now); err != nil {
		t.Fatalf("valid intent rejected: %v", err)
	}
	tampered := intent
	tampered.Action = "wallet.topup"
	if err := tampered.Verify(publicKey, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered intent error = %v", err)
	}
	if err := intent.Verify(publicKey, time.Unix(intent.ExpiresAt+1, 0)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired intent error = %v", err)
	}
}

func TestDecisionVerifyForBindsIntentTenantAgentAndTime(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	decision := Decision{
		Version:         SchemaVersion,
		ID:              "decision-001",
		IntentHash:      intentHash,
		TenantID:        intent.TenantID,
		AgentID:         intent.AgentID,
		Outcome:         Constrain,
		Reasons:         []string{"amount is within mandate"},
		Constraints:     []Constraint{{Key: "amount_usdc", Operator: "max", Value: "25.00"}},
		PolicyRevision:  42,
		RevocationEpoch: 3,
		ProviderID:      "pilot-managed-eu1",
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(time.Minute).Unix(),
		KeyID:           "decision-key-9",
	}
	if err := decision.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := decision.VerifyFor(intent, publicKey, now); err != nil {
		t.Fatalf("valid decision rejected: %v", err)
	}

	otherTenant := intent
	otherTenant.TenantID = "tenant-other"
	if err := decision.VerifyFor(otherTenant, publicKey, now); err == nil {
		t.Fatal("cross-tenant decision replay accepted")
	}
	wider := decision
	wider.ExpiresAt = intent.ExpiresAt + 1
	if err := wider.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	if err := wider.VerifyFor(intent, publicKey, now); err == nil || !strings.Contains(err.Error(), "expands") {
		t.Fatalf("authority-expanding expiry error = %v", err)
	}
}

func TestConstraintOrderIsCanonicalAndUnknownOperatorFails(t *testing.T) {
	t.Parallel()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0)
	base := Decision{
		Version: SchemaVersion, ID: "decision-order", IntentHash: strings.Repeat("a", 64),
		TenantID: "tenant-acme", AgentID: "agent-one", Outcome: Constrain,
		Constraints: []Constraint{
			{Key: "recipient", Operator: "one_of", Value: "vendor-a,vendor-b"},
			{Key: "amount", Operator: "max", Value: "100"},
		},
		ProviderID: "local", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), KeyID: "issuer-1",
	}
	if err := base.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	reordered := base
	reordered.Constraints = []Constraint{base.Constraints[1], base.Constraints[0]}
	baseCanonical, _ := base.Canonical()
	reorderedCanonical, _ := reordered.Canonical()
	if string(baseCanonical) != string(reorderedCanonical) {
		t.Fatal("constraint reordering changed canonical form")
	}
	reordered.Constraints[0].Operator = "execute"
	if err := reordered.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown operator error = %v", err)
	}
}
