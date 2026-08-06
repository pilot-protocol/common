// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestApprovalConformanceVector(t *testing.T) {
	decisionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	approvalPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	intent := Intent{
		Version: SchemaVersion, ID: "approval-vector-intent", TenantID: "tenant-vector", AgentID: "agent-vector",
		Action: "wallet.pay", Resource: "invoice/vector", PayloadHash: HashPayload([]byte("vector")), Risk: RiskHigh,
		IssuedAt: 1785500000, ExpiresAt: 1785500120, Nonce: strings.Repeat("0", 32), KeyID: "agent-key",
	}
	intentHash, _ := intent.Hash()
	initial := Decision{
		Version: SchemaVersion, ID: "approval-vector-decision", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: ApprovalRequired,
		PolicyRevision: 4, RevocationEpoch: 2, ProviderID: "vector-provider",
		IssuedAt: 1785500000, ExpiresAt: 1785500120, KeyID: "decision-key",
	}
	_ = initial.Sign(decisionPrivate)
	request, err := NewApprovalRequest(intent, initial)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewApprovalGrant(request, "approver-vector", Allow, nil, time.Unix(1785500030, 0), time.Unix(1785500100, 0), strings.Repeat("1", 32), "approval-key")
	if err != nil {
		t.Fatal(err)
	}
	_ = grant.Sign(approvalPrivate)
	requestHash, _ := request.Hash()
	grantHash, _ := grant.Hash()
	const expectedRequestHash = "d346725bf8dd865e31286411094bf4cc3454de877dffae2942a72a94a180108c"
	const expectedGrantHash = "92da335aa12c523693d9cc711bfc092d96c38f293364c7ebe6977485394abaee"
	const expectedGrantSignature = "lFs4C50SVSUrYLb10cj3PYURRwfgxEz4JSxpjK/74tR+QvuelHOpwlfDvp7dCo09R7dZpTyX91m4el+ZhdMLDQ=="
	if requestHash != expectedRequestHash || grantHash != expectedGrantHash || grant.Signature != expectedGrantSignature {
		t.Fatalf("update vector: request=%s grant=%s signature=%s", requestHash, grantHash, grant.Signature)
	}
}

func approvalFixture(t *testing.T) (Intent, Decision, ApprovalRequest, ApprovalGrant, Decision, ed25519.PublicKey, ed25519.PrivateKey, ed25519.PublicKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	decisionPublic, decisionPrivate, _ := ed25519.GenerateKey(rand.Reader)
	approvalPublic, approvalPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1785500000, 0)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	initial := Decision{
		Version: SchemaVersion, ID: "approval-needed", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: ApprovalRequired,
		Reasons: []string{"human approval required"}, PolicyRevision: 7, RevocationEpoch: 2,
		ProviderID: "managed", IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "decision-key-1",
	}
	if err := initial.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	request, err := NewApprovalRequest(intent, initial)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := NewApprovalGrant(
		request, "approver-1", Constrain,
		[]Constraint{{Key: "amount", Operator: "max", Value: "100"}},
		now.Add(30*time.Second), now.Add(110*time.Second), strings.Repeat("1", 32), "approval-key-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Sign(approvalPrivate); err != nil {
		t.Fatal(err)
	}
	reason, _ := grant.EvidenceReason()
	final := Decision{
		Version: SchemaVersion, ID: "approval-final", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: Constrain,
		Reasons: []string{reason}, Constraints: append([]Constraint(nil), grant.Constraints...),
		PolicyRevision: 7, RevocationEpoch: 2, ProviderID: "managed",
		IssuedAt: now.Add(30 * time.Second).Unix(), ExpiresAt: now.Add(100 * time.Second).Unix(), KeyID: "decision-key-1",
	}
	if err := final.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	return intent, initial, request, grant, final, decisionPublic, decisionPrivate, approvalPublic, approvalPrivate, now
}

func TestApprovedDecisionEvidenceIsFullyBound(t *testing.T) {
	t.Parallel()
	intent, initial, request, grant, final, decisionKey, _, approvalKey, _, now := approvalFixture(t)
	if err := VerifyApprovedDecision(intent, initial, final, request, grant, decisionKey, approvalKey, now.Add(45*time.Second)); err != nil {
		t.Fatalf("valid approved decision rejected: %v", err)
	}
	tampered := final
	tampered.Constraints = []Constraint{{Key: "amount", Operator: "max", Value: "1000"}}
	if err := VerifyApprovedDecision(intent, initial, tampered, request, grant, decisionKey, approvalKey, now.Add(45*time.Second)); err == nil {
		t.Fatal("expanded final constraint was accepted")
	}
	tampered = final
	tampered.Reasons = []string{"approval:" + strings.Repeat("0", 64)}
	if err := VerifyApprovedDecision(intent, initial, tampered, request, grant, decisionKey, approvalKey, now.Add(45*time.Second)); err == nil {
		t.Fatal("final decision without bound approval hash was accepted")
	}
}

func TestApprovalGrantRejectsTamperCrossRequestAndExpiry(t *testing.T) {
	t.Parallel()
	intent, initial, request, grant, _, _, _, approvalKey, _, now := approvalFixture(t)
	wrongRequest := request
	wrongRequest.IntentHash = strings.Repeat("a", 64)
	wrongRequest.ID = approvalRequestID(wrongRequest.IntentHash, wrongRequest.DecisionID)
	if err := grant.VerifyFor(wrongRequest, approvalKey, now.Add(45*time.Second)); err == nil {
		t.Fatal("approval grant crossed requests")
	}
	tampered := grant
	tampered.ApproverID = "approver-2"
	tampered.ID = approvalGrantID(tampered.RequestHash, tampered.ApproverID, tampered.Nonce)
	if err := tampered.VerifyFor(request, approvalKey, now.Add(45*time.Second)); err == nil {
		t.Fatal("tampered approval grant was accepted")
	}
	if err := grant.VerifyFor(request, approvalKey, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired approval grant was accepted")
	}
	otherIntent := intent
	otherIntent.ID = "another-intent"
	if err := request.ValidateFor(otherIntent, initial); err == nil {
		t.Fatal("approval request crossed intents")
	}
}

func TestIssueApprovedDecisionProducesLocallyVerifiableResult(t *testing.T) {
	t.Parallel()
	intent, initial, request, grant, _, decisionPublic, decisionPrivate, approvalPublic, _, now := approvalFixture(t)
	final, err := IssueApprovedDecision(
		intent, initial, request, grant, decisionPublic, approvalPublic, decisionPrivate,
		"managed", "decision-key-1", now.Add(45*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyApprovedDecision(intent, initial, final, request, grant, decisionPublic, approvalPublic, now.Add(45*time.Second)); err != nil {
		t.Fatalf("issued approved decision did not verify: %v", err)
	}
}
