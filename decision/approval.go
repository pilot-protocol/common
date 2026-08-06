// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	ApprovalRequestDomain = "pilot-approval-request-v1"
	ApprovalGrantDomain   = "pilot-approval-grant-v1"
)

// ApprovalRequest is a deterministic view of one signed
// approval_required decision. It adds no authority by itself.
type ApprovalRequest struct {
	Version         uint16 `json:"version"`
	ID              string `json:"id"`
	IntentHash      string `json:"intent_hash"`
	DecisionID      string `json:"decision_id"`
	DecisionHash    string `json:"decision_hash"`
	TenantID        string `json:"tenant_id"`
	AgentID         string `json:"agent_id"`
	PolicyRevision  uint64 `json:"policy_revision"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
	RequestedAt     int64  `json:"requested_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

// ApprovalGrant is a purpose-limited approver signature over one exact
// ApprovalRequest. It can allow or add constraints; it cannot be reused for a
// different intent, decision, tenant, or agent.
type ApprovalGrant struct {
	Version     uint16       `json:"version"`
	ID          string       `json:"id"`
	RequestHash string       `json:"request_hash"`
	TenantID    string       `json:"tenant_id"`
	AgentID     string       `json:"agent_id"`
	ApproverID  string       `json:"approver_id"`
	Outcome     Outcome      `json:"outcome"`
	Constraints []Constraint `json:"constraints,omitempty"`
	IssuedAt    int64        `json:"issued_at"`
	ExpiresAt   int64        `json:"expires_at"`
	Nonce       string       `json:"nonce"`
	KeyID       string       `json:"key_id"`
	Signature   string       `json:"signature"`
}

func NewApprovalRequest(intent Intent, initial Decision) (ApprovalRequest, error) {
	intentHash, err := intent.Hash()
	if err != nil {
		return ApprovalRequest{}, err
	}
	decisionHash, err := initial.Hash()
	if err != nil {
		return ApprovalRequest{}, err
	}
	request := ApprovalRequest{
		Version: SchemaVersion, ID: approvalRequestID(intentHash, initial.ID),
		IntentHash: intentHash, DecisionID: initial.ID, DecisionHash: decisionHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID,
		PolicyRevision: initial.PolicyRevision, RevocationEpoch: initial.RevocationEpoch,
		RequestedAt: initial.IssuedAt, ExpiresAt: initial.ExpiresAt,
	}
	if err := request.ValidateFor(intent, initial); err != nil {
		return ApprovalRequest{}, err
	}
	return request, nil
}

func (request ApprovalRequest) Validate() error {
	if request.Version != SchemaVersion || !lowerHex(request.ID, 64) ||
		!lowerHex(request.IntentHash, 64) || !lowerHex(request.DecisionHash, 64) {
		return fmt.Errorf("decision: invalid approval request identity")
	}
	for name, value := range map[string]string{
		"decision_id": request.DecisionID, "tenant_id": request.TenantID, "agent_id": request.AgentID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if request.RequestedAt <= 0 || request.ExpiresAt <= request.RequestedAt ||
		request.ExpiresAt-request.RequestedAt > int64(MaxDecisionTTL/time.Second) {
		return fmt.Errorf("decision: invalid approval request validity window")
	}
	if request.ID != approvalRequestID(request.IntentHash, request.DecisionID) {
		return fmt.Errorf("decision: noncanonical approval request id")
	}
	return nil
}

func (request ApprovalRequest) ValidateFor(intent Intent, initial Decision) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if initial.Outcome != ApprovalRequired {
		return fmt.Errorf("decision: approval request requires approval_required decision")
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return err
	}
	decisionHash, err := initial.Hash()
	if err != nil {
		return err
	}
	if request.IntentHash != intentHash || request.DecisionHash != decisionHash || request.DecisionID != initial.ID ||
		request.TenantID != intent.TenantID || request.AgentID != intent.AgentID ||
		request.PolicyRevision != initial.PolicyRevision || request.RevocationEpoch != initial.RevocationEpoch ||
		request.RequestedAt != initial.IssuedAt || request.ExpiresAt != initial.ExpiresAt {
		return fmt.Errorf("decision: approval request object binding mismatch")
	}
	return nil
}

func (request ApprovalRequest) Canonical() ([]byte, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(ApprovalRequestDomain)
	writer.u16(request.Version)
	writer.string(request.ID)
	writer.string(request.IntentHash)
	writer.string(request.DecisionID)
	writer.string(request.DecisionHash)
	writer.string(request.TenantID)
	writer.string(request.AgentID)
	writer.u64(request.PolicyRevision)
	writer.u64(request.RevocationEpoch)
	writer.i64(request.RequestedAt)
	writer.i64(request.ExpiresAt)
	return writer.Bytes(), nil
}

func (request ApprovalRequest) Hash() (string, error) { return hashCanonical(request.Canonical()) }

func NewApprovalGrant(request ApprovalRequest, approverID string, outcome Outcome, constraints []Constraint, issuedAt, expiresAt time.Time, nonce, keyID string) (ApprovalGrant, error) {
	requestHash, err := request.Hash()
	if err != nil {
		return ApprovalGrant{}, err
	}
	grant := ApprovalGrant{
		Version: SchemaVersion, RequestHash: requestHash,
		TenantID: request.TenantID, AgentID: request.AgentID, ApproverID: approverID,
		Outcome: outcome, Constraints: append([]Constraint(nil), constraints...),
		IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(), Nonce: nonce, KeyID: keyID,
	}
	grant.ID = approvalGrantID(requestHash, approverID, nonce)
	if err := grant.Validate(); err != nil {
		return ApprovalGrant{}, err
	}
	return grant, nil
}

func (grant ApprovalGrant) Validate() error {
	if grant.Version != SchemaVersion || !lowerHex(grant.ID, 64) || !lowerHex(grant.RequestHash, 64) || !lowerHex(grant.Nonce, 32) {
		return fmt.Errorf("decision: invalid approval grant identity")
	}
	for name, value := range map[string]string{
		"tenant_id": grant.TenantID, "agent_id": grant.AgentID,
		"approver_id": grant.ApproverID, "key_id": grant.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if grant.Outcome != Allow && grant.Outcome != Constrain {
		return fmt.Errorf("decision: approval grant outcome must allow or constrain")
	}
	probe := Decision{
		Version: SchemaVersion, ID: "approval-validation", IntentHash: strings.Repeat("0", 64),
		TenantID: grant.TenantID, AgentID: grant.AgentID, Outcome: grant.Outcome,
		Constraints: grant.Constraints, ProviderID: "approval-validation",
		IssuedAt: 1, ExpiresAt: 2, KeyID: "approval-validation",
	}
	if err := probe.Validate(); err != nil {
		return err
	}
	if grant.IssuedAt <= 0 || grant.ExpiresAt <= grant.IssuedAt ||
		grant.ExpiresAt-grant.IssuedAt > int64(MaxDecisionTTL/time.Second) {
		return fmt.Errorf("decision: invalid approval grant validity window")
	}
	if grant.ID != approvalGrantID(grant.RequestHash, grant.ApproverID, grant.Nonce) {
		return fmt.Errorf("decision: noncanonical approval grant id")
	}
	return nil
}

func (grant ApprovalGrant) Canonical() ([]byte, error) {
	if err := grant.Validate(); err != nil {
		return nil, err
	}
	constraints := append([]Constraint(nil), grant.Constraints...)
	sort.Slice(constraints, func(i, j int) bool {
		if constraints[i].Key != constraints[j].Key {
			return constraints[i].Key < constraints[j].Key
		}
		if constraints[i].Operator != constraints[j].Operator {
			return constraints[i].Operator < constraints[j].Operator
		}
		return constraints[i].Value < constraints[j].Value
	})
	writer := canonicalWriter{}
	writer.string(ApprovalGrantDomain)
	writer.u16(grant.Version)
	writer.string(grant.ID)
	writer.string(grant.RequestHash)
	writer.string(grant.TenantID)
	writer.string(grant.AgentID)
	writer.string(grant.ApproverID)
	writer.string(string(grant.Outcome))
	writer.u16(uint16(len(constraints)))
	for _, constraint := range constraints {
		writer.string(constraint.Key)
		writer.string(constraint.Operator)
		writer.string(constraint.Value)
	}
	writer.i64(grant.IssuedAt)
	writer.i64(grant.ExpiresAt)
	writer.string(grant.Nonce)
	writer.string(grant.KeyID)
	return writer.Bytes(), nil
}

func (grant ApprovalGrant) Hash() (string, error) { return hashCanonical(grant.Canonical()) }

func (grant *ApprovalGrant) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid approval private key")
	}
	canonical, err := grant.Canonical()
	if err != nil {
		return err
	}
	grant.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (grant ApprovalGrant) VerifyFor(request ApprovalRequest, publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := grant.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFresh("approval grant", grant.IssuedAt, grant.ExpiresAt, now); err != nil {
		return err
	}
	if err := verifySignature("approval grant", publicKey, canonical, grant.Signature); err != nil {
		return err
	}
	requestHash, err := request.Hash()
	if err != nil {
		return err
	}
	if grant.RequestHash != requestHash || grant.TenantID != request.TenantID || grant.AgentID != request.AgentID ||
		grant.ExpiresAt > request.ExpiresAt || grant.IssuedAt < request.RequestedAt-int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: approval grant request binding mismatch")
	}
	return nil
}

func (grant ApprovalGrant) EvidenceReason() (string, error) {
	hash, err := grant.Hash()
	if err != nil {
		return "", err
	}
	return "approval:" + hash, nil
}

// IssueApprovedDecision is the authority-side transition from an
// approval_required result plus a valid human grant to a final signed result.
func IssueApprovedDecision(intent Intent, initial Decision, request ApprovalRequest, grant ApprovalGrant, decisionPublicKey, approvalPublicKey ed25519.PublicKey, decisionPrivateKey ed25519.PrivateKey, providerID, decisionKeyID string, now time.Time) (Decision, error) {
	if len(decisionPrivateKey) != ed25519.PrivateKeySize {
		return Decision{}, fmt.Errorf("decision: invalid decision private key")
	}
	return IssueApprovedDecisionWithSigner(intent, initial, request, grant, decisionPublicKey, approvalPublicKey,
		func(message []byte) ([]byte, error) { return ed25519.Sign(decisionPrivateKey, message), nil }, providerID, decisionKeyID, now)
}

// IssueApprovedDecisionWithSigner is the remote-key-compatible variant of
// IssueApprovedDecision. signer signs the final canonical Decision with the
// same public key that verified the initial authority decision.
func IssueApprovedDecisionWithSigner(intent Intent, initial Decision, request ApprovalRequest, grant ApprovalGrant, decisionPublicKey, approvalPublicKey ed25519.PublicKey, signer func([]byte) ([]byte, error), providerID, decisionKeyID string, now time.Time) (Decision, error) {
	if signer == nil {
		return Decision{}, fmt.Errorf("decision: decision signer is required")
	}
	if err := initial.VerifyFor(intent, decisionPublicKey, now); err != nil {
		return Decision{}, fmt.Errorf("decision: initial approval decision: %w", err)
	}
	if err := request.ValidateFor(intent, initial); err != nil {
		return Decision{}, err
	}
	if err := grant.VerifyFor(request, approvalPublicKey, now); err != nil {
		return Decision{}, err
	}
	grantHash, err := grant.Hash()
	if err != nil {
		return Decision{}, err
	}
	expiresAt := grant.ExpiresAt
	if expiresAt > intent.ExpiresAt {
		expiresAt = intent.ExpiresAt
	}
	if expiresAt <= now.Unix() {
		return Decision{}, fmt.Errorf("decision: approval expires before final decision")
	}
	intentHash, _ := intent.Hash()
	final := Decision{
		Version: SchemaVersion, ID: domainHash("pilot-approved-decision-v1/id", initial.ID, grantHash),
		IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: grant.Outcome, Reasons: []string{"approval:" + grantHash},
		Constraints:    append([]Constraint(nil), grant.Constraints...),
		PolicyRevision: initial.PolicyRevision, RevocationEpoch: initial.RevocationEpoch,
		ProviderID: providerID, IssuedAt: now.Unix(), ExpiresAt: expiresAt, KeyID: decisionKeyID,
	}
	if err := final.SignWith(signer); err != nil {
		return Decision{}, err
	}
	if err := final.Verify(decisionPublicKey, now); err != nil {
		return Decision{}, fmt.Errorf("decision: issued approved decision key mismatch: %w", err)
	}
	return final, nil
}

// VerifyApprovedDecision validates the complete local evidence package for a
// final allow/constrain issued after human approval.
func VerifyApprovedDecision(intent Intent, initial, final Decision, request ApprovalRequest, grant ApprovalGrant, decisionKey, approvalKey ed25519.PublicKey, now time.Time) error {
	if err := initial.VerifyFor(intent, decisionKey, now); err != nil {
		return fmt.Errorf("decision: initial approval decision: %w", err)
	}
	if err := request.ValidateFor(intent, initial); err != nil {
		return err
	}
	if err := grant.VerifyFor(request, approvalKey, now); err != nil {
		return err
	}
	if err := final.VerifyFor(intent, decisionKey, now); err != nil {
		return fmt.Errorf("decision: final approved decision: %w", err)
	}
	if final.Outcome != grant.Outcome || !constraintsEqual(final.Constraints, grant.Constraints) ||
		final.PolicyRevision < request.PolicyRevision || final.RevocationEpoch < request.RevocationEpoch ||
		final.IssuedAt < grant.IssuedAt-int64(MaxClockSkew/time.Second) || final.ExpiresAt > grant.ExpiresAt {
		return fmt.Errorf("decision: final decision exceeds approval grant")
	}
	reason, _ := grant.EvidenceReason()
	for _, candidate := range final.Reasons {
		if candidate == reason {
			return nil
		}
	}
	return fmt.Errorf("decision: final decision does not bind approval evidence")
}

func approvalRequestID(intentHash, decisionID string) string {
	return domainHash(ApprovalRequestDomain+"/id", intentHash, decisionID)
}

func approvalGrantID(requestHash, approverID, nonce string) string {
	return domainHash(ApprovalGrantDomain+"/id", requestHash, approverID, nonce)
}

func domainHash(domain string, values ...string) string {
	hash := sha256.New()
	writer := canonicalWriter{}
	writer.string(domain)
	for _, value := range values {
		writer.string(value)
	}
	hash.Write(writer.Bytes())
	return hex.EncodeToString(hash.Sum(nil))
}

func constraintsEqual(first, second []Constraint) bool {
	if len(first) != len(second) {
		return false
	}
	key := func(constraint Constraint) string {
		return constraint.Key + "\x00" + constraint.Operator + "\x00" + constraint.Value
	}
	counts := make(map[string]int, len(first))
	for _, constraint := range first {
		counts[key(constraint)]++
	}
	for _, constraint := range second {
		identity := key(constraint)
		if counts[identity] == 0 {
			return false
		}
		counts[identity]--
	}
	return true
}
