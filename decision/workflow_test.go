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

func TestLongApprovalConformanceVector(t *testing.T) {
	decisionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	approvalPrivate1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x88}, ed25519.SeedSize))
	approvalPrivate2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	now := time.Unix(1785500000, 0)
	intent := Intent{
		Version: SchemaVersion, ID: "workflow-vector-intent", TenantID: "tenant-vector", AgentID: "agent-vector",
		Action: "wallet.pay", Resource: "invoice/vector", PayloadHash: HashPayload([]byte("workflow-vector")), Risk: RiskCritical,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: strings.Repeat("a", 32), KeyID: "agent-key-vector",
	}
	intentHash, _ := intent.Hash()
	initial := Decision{
		Version: SchemaVersion, ID: "workflow-vector-decision", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: ApprovalRequired,
		PolicyRevision: 12, RevocationEpoch: 4, ProviderID: "workflow-vector-provider",
		IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "decision-key-vector",
	}
	_ = initial.Sign(decisionPrivate)
	transaction, err := NewApprovalTransaction(
		intent, initial, Constrain, []Constraint{{Key: "amount", Operator: "max", Value: "500"}},
		[]string{"approval-key-b", "approval-key-a"}, 2, now, now.Add(24*time.Hour),
		"workflow-vector-provider", "decision-key-vector",
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = transaction.Sign(decisionPrivate)
	vote1, _ := NewApprovalVote(transaction, "approver-a", ApprovalVoteApprove, now.Add(time.Hour), now.Add(20*time.Hour), strings.Repeat("b", 32), "approval-key-a")
	_ = vote1.Sign(approvalPrivate1)
	vote2, _ := NewApprovalVote(transaction, "approver-b", ApprovalVoteApprove, now.Add(90*time.Minute), now.Add(22*time.Hour), strings.Repeat("c", 32), "approval-key-b")
	_ = vote2.Sign(approvalPrivate2)
	keys := map[string]ed25519.PublicKey{
		"approval-key-a": approvalPrivate1.Public().(ed25519.PublicKey),
		"approval-key-b": approvalPrivate2.Public().(ed25519.PublicKey),
	}
	certificate, err := IssueApprovalCertificate(transaction, []ApprovalVote{vote2, vote1}, keys, decisionPrivate, now.Add(2*time.Hour), "workflow-vector-provider", "decision-key-vector")
	if err != nil {
		t.Fatal(err)
	}
	transactionHash, _ := transaction.Hash()
	vote1Hash, _ := vote1.Hash()
	vote2Hash, _ := vote2.Hash()
	certificateHash, _ := certificate.Hash()
	const expectedTransactionHash = "d58a72d62c189cc8ccb07adf4e9324d8694b2c3d50714d3f419a3c57556057f2"
	const expectedTransactionSignature = "VY1k9QlfVoz8giiL/r9sT81cl+IrRxRXGtGkxQW1J9w7IiqUmIBDLtr27EcfneHMKvWFziZ6R/xitB4H2882AA=="
	const expectedVote1Hash = "919ba22460608de5ceb9be6eb2ce4730b770cb598731b6a1b80732c4de3aa96a"
	const expectedVote1Signature = "J+hSN+QAV/fk9XZozZU0td/PCYmT8FM8k+qd5sp02MoWUQGMRgWATePoHDk6X5cEo55+ZfTUOr6Ez2OtGiEhBw=="
	const expectedVote2Hash = "4514256a97752c76a052c30e5055ea132ab40c9610a69699a5c8d2c25e16cc7c"
	const expectedVote2Signature = "jp/t2CZUyOd5GSq4z5KRO2wBJCwiJFxxsfXyLqrBYK7RO5Jm4X2CBLIb9EtDNQUyZDs2Z/gvMozylfUq7olGCQ=="
	const expectedCertificateHash = "7f4d608a560df1c49e1cfac6ba75187ee8a6b6b10a7ac16eb3e2f501e1c35fc2"
	const expectedCertificateSignature = "R+n7zwZS5WpTWlA5fKsMRDX+dc8rpdqh3dkntzL8bhugaELFx90ANImixhR9yUtrzNdKLQ1UhaOjvOz51LtiAQ=="
	if transactionHash != expectedTransactionHash || transaction.Signature != expectedTransactionSignature ||
		vote1Hash != expectedVote1Hash || vote1.Signature != expectedVote1Signature ||
		vote2Hash != expectedVote2Hash || vote2.Signature != expectedVote2Signature ||
		certificateHash != expectedCertificateHash || certificate.Signature != expectedCertificateSignature {
		t.Fatalf("update vector: transaction_hash=%s transaction_signature=%s vote1_hash=%s vote1_signature=%s vote2_hash=%s vote2_signature=%s certificate_hash=%s certificate_signature=%s",
			transactionHash, transaction.Signature, vote1Hash, vote1.Signature, vote2Hash, vote2.Signature, certificateHash, certificate.Signature)
	}
}

func TestApprovalCancellationBindsTransactionAndIsFresh(t *testing.T) {
	t.Parallel()
	fixture := newWorkflowFixture(t)
	cancellation, err := NewApprovalCancellation(fixture.transaction, "operator cancelled", fixture.now, "managed-workflow", "decision-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := cancellation.Sign(fixture.decisionPrivate); err != nil {
		t.Fatal(err)
	}
	if err := cancellation.VerifyFor(fixture.transaction, fixture.decisionPublic, fixture.now); err != nil {
		t.Fatal(err)
	}
	tampered := cancellation
	tampered.Reason = "changed"
	if err := tampered.VerifyFor(fixture.transaction, fixture.decisionPublic, fixture.now); err == nil {
		t.Fatal("tampered cancellation was accepted")
	}
	if err := cancellation.VerifyFor(fixture.transaction, fixture.decisionPublic, fixture.now.Add(MaxClockSkew+time.Second)); err == nil {
		t.Fatal("stale cancellation was accepted")
	}
}

type workflowFixture struct {
	now              time.Time
	intent           Intent
	initial          Decision
	transaction      ApprovalTransaction
	votes            []ApprovalVote
	certificate      ApprovalCertificate
	decisionPublic   ed25519.PublicKey
	decisionPrivate  ed25519.PrivateKey
	approvalPublic1  ed25519.PublicKey
	approvalPrivate1 ed25519.PrivateKey
	approvalPublic2  ed25519.PublicKey
	approvalPrivate2 ed25519.PrivateKey
}

func newWorkflowFixture(t *testing.T) workflowFixture {
	t.Helper()
	now := time.Unix(1785500000, 0)
	decisionPublic, decisionPrivate, _ := ed25519.GenerateKey(rand.Reader)
	approvalPublic1, approvalPrivate1, _ := ed25519.GenerateKey(rand.Reader)
	approvalPublic2, approvalPrivate2, _ := ed25519.GenerateKey(rand.Reader)
	intent := testIntent(t, now)
	intentHash, _ := intent.Hash()
	initial := Decision{
		Version: SchemaVersion, ID: "workflow-initial", IntentHash: intentHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Outcome: ApprovalRequired,
		PolicyRevision: 9, RevocationEpoch: 3, ProviderID: "managed-workflow",
		IssuedAt: now.Unix(), ExpiresAt: intent.ExpiresAt, KeyID: "decision-key-1",
	}
	if err := initial.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	transaction, err := NewApprovalTransaction(
		intent, initial, Constrain, []Constraint{{Key: "amount", Operator: "max", Value: "100"}},
		[]string{"approval-key-2", "approval-key-1"}, 2, now, now.Add(24*time.Hour),
		"managed-workflow", "decision-key-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	vote1, err := NewApprovalVote(transaction, "approver-1", ApprovalVoteApprove, now.Add(time.Hour), now.Add(20*time.Hour), strings.Repeat("1", 32), "approval-key-1")
	if err != nil {
		t.Fatal(err)
	}
	_ = vote1.Sign(approvalPrivate1)
	vote2, err := NewApprovalVote(transaction, "approver-2", ApprovalVoteApprove, now.Add(90*time.Minute), now.Add(22*time.Hour), strings.Repeat("2", 32), "approval-key-2")
	if err != nil {
		t.Fatal(err)
	}
	_ = vote2.Sign(approvalPrivate2)
	keys := map[string]ed25519.PublicKey{"approval-key-1": approvalPublic1, "approval-key-2": approvalPublic2}
	certificate, err := IssueApprovalCertificate(transaction, []ApprovalVote{vote2, vote1}, keys, decisionPrivate, now.Add(2*time.Hour), "managed-workflow", "decision-key-1")
	if err != nil {
		t.Fatal(err)
	}
	return workflowFixture{
		now: now, intent: intent, initial: initial, transaction: transaction,
		votes: []ApprovalVote{vote1, vote2}, certificate: certificate,
		decisionPublic: decisionPublic, decisionPrivate: decisionPrivate,
		approvalPublic1: approvalPublic1, approvalPrivate1: approvalPrivate1,
		approvalPublic2: approvalPublic2, approvalPrivate2: approvalPrivate2,
	}
}

func TestLongApprovalBindsThresholdToFreshExecutionIntent(t *testing.T) {
	t.Parallel()
	fixture := newWorkflowFixture(t)
	fresh := fixture.intent
	fresh.ID = "workflow-execution"
	fresh.IssuedAt = fixture.now.Add(2 * time.Hour).Unix()
	fresh.ExpiresAt = fixture.now.Add(2*time.Hour + 2*time.Minute).Unix()
	fresh.Nonce = strings.Repeat("3", 32)
	fresh.Signature = ""
	keys := map[string]ed25519.PublicKey{"approval-key-1": fixture.approvalPublic1, "approval-key-2": fixture.approvalPublic2}
	if err := VerifyApprovedExecution(fresh, fixture.transaction, fixture.certificate, fixture.votes, keys, fixture.decisionPublic, fixture.now.Add(2*time.Hour)); err != nil {
		t.Fatalf("valid long approval rejected: %v", err)
	}
	reordered := []ApprovalVote{fixture.votes[1], fixture.votes[0]}
	if err := fixture.certificate.VerifyFor(fixture.transaction, reordered, keys, fixture.decisionPublic, fixture.now.Add(2*time.Hour)); err != nil {
		t.Fatalf("vote ordering changed certificate semantics: %v", err)
	}
	tampered := fresh
	tampered.Resource = "invoice/another"
	if err := VerifyApprovedExecution(tampered, fixture.transaction, fixture.certificate, fixture.votes, keys, fixture.decisionPublic, fixture.now.Add(2*time.Hour)); err == nil {
		t.Fatal("approval certificate crossed action resource")
	}
	if err := VerifyApprovedExecution(fresh, fixture.transaction, fixture.certificate, fixture.votes, keys, fixture.decisionPublic, fixture.now.Add(21*time.Hour)); err == nil {
		t.Fatal("expired approval certificate was accepted")
	}
}

func TestLongApprovalRejectsMissingDuplicateUnlistedAndRejectVotes(t *testing.T) {
	t.Parallel()
	fixture := newWorkflowFixture(t)
	keys := map[string]ed25519.PublicKey{"approval-key-1": fixture.approvalPublic1, "approval-key-2": fixture.approvalPublic2}
	if _, err := IssueApprovalCertificate(fixture.transaction, fixture.votes[:1], keys, fixture.decisionPrivate, fixture.now.Add(2*time.Hour), "managed-workflow", "decision-key-1"); err == nil {
		t.Fatal("one vote satisfied a two-key threshold")
	}
	duplicate, _ := NewApprovalVote(fixture.transaction, "approver-duplicate", ApprovalVoteApprove, fixture.now.Add(100*time.Minute), fixture.now.Add(20*time.Hour), strings.Repeat("4", 32), "approval-key-1")
	_ = duplicate.Sign(fixture.approvalPrivate1)
	if _, err := IssueApprovalCertificate(fixture.transaction, []ApprovalVote{fixture.votes[0], duplicate}, keys, fixture.decisionPrivate, fixture.now.Add(2*time.Hour), "managed-workflow", "decision-key-1"); err == nil {
		t.Fatal("one approval key was counted twice")
	}
	rejected, _ := NewApprovalVote(fixture.transaction, "approver-2", ApprovalVoteReject, fixture.now.Add(90*time.Minute), fixture.now.Add(22*time.Hour), strings.Repeat("5", 32), "approval-key-2")
	_ = rejected.Sign(fixture.approvalPrivate2)
	if _, err := IssueApprovalCertificate(fixture.transaction, []ApprovalVote{fixture.votes[0], rejected}, keys, fixture.decisionPrivate, fixture.now.Add(2*time.Hour), "managed-workflow", "decision-key-1"); err == nil {
		t.Fatal("rejected workflow produced a certificate")
	}
	thirdPublic, thirdPrivate, _ := ed25519.GenerateKey(rand.Reader)
	unlisted, _ := NewApprovalVote(fixture.transaction, "approver-3", ApprovalVoteApprove, fixture.now.Add(time.Hour), fixture.now.Add(20*time.Hour), strings.Repeat("6", 32), "approval-key-3")
	_ = unlisted.Sign(thirdPrivate)
	keys["approval-key-3"] = thirdPublic
	if _, err := IssueApprovalCertificate(fixture.transaction, []ApprovalVote{fixture.votes[0], unlisted}, keys, fixture.decisionPrivate, fixture.now.Add(2*time.Hour), "managed-workflow", "decision-key-1"); err == nil {
		t.Fatal("unlisted approval key satisfied threshold")
	}
}

func TestLongApprovalObjectsRejectAuthorityExpansionAndTamper(t *testing.T) {
	t.Parallel()
	fixture := newWorkflowFixture(t)
	if _, err := NewApprovalTransaction(
		fixture.intent, fixture.initial, Allow, []Constraint{{Key: "amount", Operator: "max", Value: "1000"}},
		[]string{"approval-key-1"}, 1, fixture.now, fixture.now.Add(time.Hour), "managed", "decision-key-1",
	); err == nil {
		t.Fatal("allow transaction carried constraints")
	}
	tampered := fixture.certificate
	tampered.Constraints[0].Value = "1000"
	keys := map[string]ed25519.PublicKey{"approval-key-1": fixture.approvalPublic1, "approval-key-2": fixture.approvalPublic2}
	if err := tampered.VerifyFor(fixture.transaction, fixture.votes, keys, fixture.decisionPublic, fixture.now.Add(2*time.Hour)); err == nil {
		t.Fatal("expanded certificate constraints were accepted")
	}
	wrongDecisionPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := fixture.transaction.Verify(wrongDecisionPublic, fixture.now.Add(time.Hour)); err == nil {
		t.Fatal("transaction signed by another authority was accepted")
	}
}
