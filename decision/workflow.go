// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

const (
	ApprovalTransactionDomain = "pilot-approval-transaction-v1"
	ApprovalVoteDomain        = "pilot-approval-vote-v1"
	ApprovalCertificateDomain = "pilot-approval-certificate-v1"
	MaxApprovalTransactionTTL = 7 * 24 * time.Hour
	MaxApprovalKeys           = 32
	MaxApprovalVotes          = 32
)

type ApprovalVoteChoice string

const (
	ApprovalVoteApprove ApprovalVoteChoice = "approve"
	ApprovalVoteReject  ApprovalVoteChoice = "reject"
)

// ApprovalTransaction is a decision-authority-signed, long-lived proposal.
// Its exact action fields and proposed outcome are the maximum authority that
// a later threshold certificate can unlock.
type ApprovalTransaction struct {
	Version             uint16       `json:"version"`
	ID                  string       `json:"id"`
	InitialDecisionHash string       `json:"initial_decision_hash"`
	TenantID            string       `json:"tenant_id"`
	AgentID             string       `json:"agent_id"`
	Action              string       `json:"action"`
	Resource            string       `json:"resource"`
	PayloadHash         string       `json:"payload_hash"`
	Risk                RiskClass    `json:"risk"`
	Outcome             Outcome      `json:"outcome"`
	Constraints         []Constraint `json:"constraints,omitempty"`
	PolicyRevision      uint64       `json:"policy_revision"`
	RevocationEpoch     uint64       `json:"revocation_epoch"`
	ApproverKeyIDs      []string     `json:"approver_key_ids"`
	RequiredApprovals   uint16       `json:"required_approvals"`
	CreatedAt           int64        `json:"created_at"`
	ExpiresAt           int64        `json:"expires_at"`
	ProviderID          string       `json:"provider_id"`
	KeyID               string       `json:"key_id"`
	Signature           string       `json:"signature"`
}

// ApprovalVote is one purpose-limited approval-key vote over an exact
// transaction. Distinct key IDs, not self-asserted display names, satisfy the
// threshold.
type ApprovalVote struct {
	Version         uint16             `json:"version"`
	ID              string             `json:"id"`
	TransactionHash string             `json:"transaction_hash"`
	TenantID        string             `json:"tenant_id"`
	ApproverID      string             `json:"approver_id"`
	Choice          ApprovalVoteChoice `json:"choice"`
	IssuedAt        int64              `json:"issued_at"`
	ExpiresAt       int64              `json:"expires_at"`
	Nonce           string             `json:"nonce"`
	KeyID           string             `json:"key_id"`
	Signature       string             `json:"signature"`
}

// ApprovalCertificate is the decision authority's signed threshold result.
// It repeats the transaction's exact authority and the sorted vote hashes so
// an enforcer can verify the workflow without trusting mutable server state.
type ApprovalCertificate struct {
	Version            uint16       `json:"version"`
	ID                 string       `json:"id"`
	TransactionHash    string       `json:"transaction_hash"`
	TenantID           string       `json:"tenant_id"`
	AgentID            string       `json:"agent_id"`
	Outcome            Outcome      `json:"outcome"`
	Constraints        []Constraint `json:"constraints,omitempty"`
	PolicyRevision     uint64       `json:"policy_revision"`
	RevocationEpoch    uint64       `json:"revocation_epoch"`
	ApprovalVoteHashes []string     `json:"approval_vote_hashes"`
	FinalizedAt        int64        `json:"finalized_at"`
	ExpiresAt          int64        `json:"expires_at"`
	ProviderID         string       `json:"provider_id"`
	KeyID              string       `json:"key_id"`
	Signature          string       `json:"signature"`
}

func NewApprovalTransaction(intent Intent, initial Decision, outcome Outcome, constraints []Constraint, approverKeyIDs []string, required uint16, createdAt, expiresAt time.Time, providerID, keyID string) (ApprovalTransaction, error) {
	intentHash, err := intent.Hash()
	if err != nil {
		return ApprovalTransaction{}, err
	}
	initialHash, err := initial.Hash()
	if err != nil {
		return ApprovalTransaction{}, err
	}
	if initial.Outcome != ApprovalRequired || initial.IntentHash != intentHash || initial.TenantID != intent.TenantID || initial.AgentID != intent.AgentID {
		return ApprovalTransaction{}, fmt.Errorf("decision: long approval requires a bound approval_required decision")
	}
	if createdAt.Unix() < initial.IssuedAt-int64(MaxClockSkew/time.Second) || createdAt.Unix() > initial.ExpiresAt+int64(MaxClockSkew/time.Second) {
		return ApprovalTransaction{}, fmt.Errorf("decision: approval transaction was not created during the initial decision window")
	}
	transaction := ApprovalTransaction{
		Version: SchemaVersion, InitialDecisionHash: initialHash,
		TenantID: intent.TenantID, AgentID: intent.AgentID, Action: intent.Action,
		Resource: intent.Resource, PayloadHash: intent.PayloadHash, Risk: intent.Risk,
		Outcome: outcome, Constraints: append([]Constraint(nil), constraints...),
		PolicyRevision: initial.PolicyRevision, RevocationEpoch: initial.RevocationEpoch,
		ApproverKeyIDs: append([]string(nil), approverKeyIDs...), RequiredApprovals: required,
		CreatedAt: createdAt.Unix(), ExpiresAt: expiresAt.Unix(), ProviderID: providerID, KeyID: keyID,
	}
	transaction.ID = approvalTransactionID(transaction)
	if err := transaction.Validate(); err != nil {
		return ApprovalTransaction{}, err
	}
	return transaction, nil
}

func (transaction ApprovalTransaction) Validate() error {
	if transaction.Version != SchemaVersion || !lowerHex(transaction.ID, 64) || !lowerHex(transaction.InitialDecisionHash, 64) || !lowerHex(transaction.PayloadHash, 64) {
		return fmt.Errorf("decision: invalid approval transaction identity")
	}
	for name, value := range map[string]string{
		"tenant_id": transaction.TenantID, "agent_id": transaction.AgentID,
		"provider_id": transaction.ProviderID, "key_id": transaction.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !validAction(transaction.Action) {
		return fmt.Errorf("decision: invalid approval transaction action")
	}
	if err := validateText("resource", transaction.Resource, 1024, false); err != nil {
		return err
	}
	switch transaction.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
	default:
		return fmt.Errorf("decision: invalid approval transaction risk")
	}
	if err := validateProposedAuthority(transaction.TenantID, transaction.AgentID, transaction.Outcome, transaction.Constraints); err != nil {
		return err
	}
	if transaction.PolicyRevision == 0 || transaction.RequiredApprovals == 0 || len(transaction.ApproverKeyIDs) == 0 ||
		len(transaction.ApproverKeyIDs) > MaxApprovalKeys || int(transaction.RequiredApprovals) > len(transaction.ApproverKeyIDs) {
		return fmt.Errorf("decision: invalid approval transaction threshold")
	}
	seen := make(map[string]struct{}, len(transaction.ApproverKeyIDs))
	for _, keyID := range transaction.ApproverKeyIDs {
		if err := validateIdentifier("approver_key_id", keyID); err != nil {
			return err
		}
		if _, exists := seen[keyID]; exists {
			return fmt.Errorf("decision: duplicate approval transaction key")
		}
		seen[keyID] = struct{}{}
	}
	if transaction.CreatedAt <= 0 || transaction.ExpiresAt <= transaction.CreatedAt ||
		transaction.ExpiresAt-transaction.CreatedAt > int64(MaxApprovalTransactionTTL/time.Second) {
		return fmt.Errorf("decision: invalid approval transaction validity window")
	}
	if transaction.ID != approvalTransactionID(transaction) {
		return fmt.Errorf("decision: noncanonical approval transaction id")
	}
	return nil
}

func (transaction ApprovalTransaction) Canonical() ([]byte, error) {
	if err := transaction.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(ApprovalTransactionDomain)
	writer.u16(transaction.Version)
	writer.string(transaction.ID)
	writer.string(transaction.InitialDecisionHash)
	writer.string(transaction.TenantID)
	writer.string(transaction.AgentID)
	writer.string(transaction.Action)
	writer.string(transaction.Resource)
	writer.string(transaction.PayloadHash)
	writer.string(string(transaction.Risk))
	writeProposedAuthority(&writer, transaction.Outcome, transaction.Constraints)
	writer.u64(transaction.PolicyRevision)
	writer.u64(transaction.RevocationEpoch)
	keys := append([]string(nil), transaction.ApproverKeyIDs...)
	sort.Strings(keys)
	writer.u16(uint16(len(keys)))
	for _, keyID := range keys {
		writer.string(keyID)
	}
	writer.u16(transaction.RequiredApprovals)
	writer.i64(transaction.CreatedAt)
	writer.i64(transaction.ExpiresAt)
	writer.string(transaction.ProviderID)
	writer.string(transaction.KeyID)
	return writer.Bytes(), nil
}

func (transaction ApprovalTransaction) Hash() (string, error) {
	return hashCanonical(transaction.Canonical())
}

func (transaction *ApprovalTransaction) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid approval transaction private key")
	}
	return transaction.SignWith(func(message []byte) ([]byte, error) { return ed25519.Sign(privateKey, message), nil })
}

func (transaction *ApprovalTransaction) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := transaction.Canonical()
	if err != nil {
		return err
	}
	return setWorkflowSignature("approval transaction", &transaction.Signature, canonical, signer)
}

func (transaction ApprovalTransaction) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := transaction.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFreshLong("approval transaction", transaction.CreatedAt, transaction.ExpiresAt, now, MaxApprovalTransactionTTL); err != nil {
		return err
	}
	return verifySignature("approval transaction", publicKey, canonical, transaction.Signature)
}

func (transaction ApprovalTransaction) MatchesIntent(intent Intent) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if transaction.TenantID != intent.TenantID || transaction.AgentID != intent.AgentID || transaction.Action != intent.Action ||
		transaction.Resource != intent.Resource || transaction.PayloadHash != intent.PayloadHash || transaction.Risk != intent.Risk {
		return fmt.Errorf("decision: approval transaction does not match execution intent")
	}
	return nil
}

func NewApprovalVote(transaction ApprovalTransaction, approverID string, choice ApprovalVoteChoice, issuedAt, expiresAt time.Time, nonce, keyID string) (ApprovalVote, error) {
	transactionHash, err := transaction.Hash()
	if err != nil {
		return ApprovalVote{}, err
	}
	vote := ApprovalVote{
		Version: SchemaVersion, TransactionHash: transactionHash, TenantID: transaction.TenantID,
		ApproverID: approverID, Choice: choice, IssuedAt: issuedAt.Unix(), ExpiresAt: expiresAt.Unix(),
		Nonce: nonce, KeyID: keyID,
	}
	vote.ID = approvalVoteID(vote)
	if err := vote.Validate(); err != nil {
		return ApprovalVote{}, err
	}
	return vote, nil
}

func (vote ApprovalVote) Validate() error {
	if vote.Version != SchemaVersion || !lowerHex(vote.ID, 64) || !lowerHex(vote.TransactionHash, 64) || !lowerHex(vote.Nonce, 32) {
		return fmt.Errorf("decision: invalid approval vote identity")
	}
	for name, value := range map[string]string{"tenant_id": vote.TenantID, "approver_id": vote.ApproverID, "key_id": vote.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if vote.Choice != ApprovalVoteApprove && vote.Choice != ApprovalVoteReject {
		return fmt.Errorf("decision: invalid approval vote choice")
	}
	if vote.IssuedAt <= 0 || vote.ExpiresAt <= vote.IssuedAt || vote.ExpiresAt-vote.IssuedAt > int64(MaxApprovalTransactionTTL/time.Second) {
		return fmt.Errorf("decision: invalid approval vote validity window")
	}
	if vote.ID != approvalVoteID(vote) {
		return fmt.Errorf("decision: noncanonical approval vote id")
	}
	return nil
}

func (vote ApprovalVote) Canonical() ([]byte, error) {
	if err := vote.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(ApprovalVoteDomain)
	writer.u16(vote.Version)
	writer.string(vote.ID)
	writer.string(vote.TransactionHash)
	writer.string(vote.TenantID)
	writer.string(vote.ApproverID)
	writer.string(string(vote.Choice))
	writer.i64(vote.IssuedAt)
	writer.i64(vote.ExpiresAt)
	writer.string(vote.Nonce)
	writer.string(vote.KeyID)
	return writer.Bytes(), nil
}

func (vote ApprovalVote) Hash() (string, error) { return hashCanonical(vote.Canonical()) }

func (vote *ApprovalVote) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid approval vote private key")
	}
	return vote.SignWith(func(message []byte) ([]byte, error) { return ed25519.Sign(privateKey, message), nil })
}

func (vote *ApprovalVote) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := vote.Canonical()
	if err != nil {
		return err
	}
	return setWorkflowSignature("approval vote", &vote.Signature, canonical, signer)
}

func (vote ApprovalVote) VerifyFor(transaction ApprovalTransaction, publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := vote.Canonical()
	if err != nil {
		return err
	}
	transactionHash, err := transaction.Hash()
	if err != nil {
		return err
	}
	if vote.TransactionHash != transactionHash || vote.TenantID != transaction.TenantID || !containsString(transaction.ApproverKeyIDs, vote.KeyID) ||
		vote.IssuedAt < transaction.CreatedAt-int64(MaxClockSkew/time.Second) || vote.ExpiresAt > transaction.ExpiresAt {
		return fmt.Errorf("decision: approval vote transaction binding mismatch")
	}
	if err := verifyFreshLong("approval vote", vote.IssuedAt, vote.ExpiresAt, now, MaxApprovalTransactionTTL); err != nil {
		return err
	}
	return verifySignature("approval vote", publicKey, canonical, vote.Signature)
}

func IssueApprovalCertificate(transaction ApprovalTransaction, votes []ApprovalVote, approvalKeys map[string]ed25519.PublicKey, decisionPrivateKey ed25519.PrivateKey, finalizedAt time.Time, providerID, keyID string) (ApprovalCertificate, error) {
	if len(decisionPrivateKey) != ed25519.PrivateKeySize {
		return ApprovalCertificate{}, fmt.Errorf("decision: invalid approval certificate private key")
	}
	certificate, err := NewApprovalCertificate(transaction, votes, approvalKeys, decisionPrivateKey.Public().(ed25519.PublicKey), finalizedAt, providerID, keyID)
	if err != nil {
		return ApprovalCertificate{}, err
	}
	if err := certificate.Sign(decisionPrivateKey); err != nil {
		return ApprovalCertificate{}, err
	}
	return certificate, nil
}

func NewApprovalCertificate(transaction ApprovalTransaction, votes []ApprovalVote, approvalKeys map[string]ed25519.PublicKey, decisionPublicKey ed25519.PublicKey, finalizedAt time.Time, providerID, keyID string) (ApprovalCertificate, error) {
	if len(votes) == 0 || len(votes) > MaxApprovalVotes {
		return ApprovalCertificate{}, fmt.Errorf("decision: invalid approval vote count")
	}
	if err := transaction.Verify(decisionPublicKey, finalizedAt); err != nil {
		return ApprovalCertificate{}, err
	}
	transactionHash, err := transaction.Hash()
	if err != nil {
		return ApprovalCertificate{}, err
	}
	seenKeys := make(map[string]struct{}, len(votes))
	voteHashes := make([]string, 0, len(votes))
	expiresAt := transaction.ExpiresAt
	approved := 0
	for _, vote := range votes {
		publicKey, exists := approvalKeys[vote.KeyID]
		if !exists {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval vote key is unavailable")
		}
		if err := vote.VerifyFor(transaction, publicKey, finalizedAt); err != nil {
			return ApprovalCertificate{}, err
		}
		if _, duplicate := seenKeys[vote.KeyID]; duplicate {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval threshold repeats a key")
		}
		seenKeys[vote.KeyID] = struct{}{}
		if vote.Choice == ApprovalVoteReject {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval transaction was rejected")
		}
		approved++
		if vote.ExpiresAt < expiresAt {
			expiresAt = vote.ExpiresAt
		}
		hash, _ := vote.Hash()
		voteHashes = append(voteHashes, hash)
	}
	if approved < int(transaction.RequiredApprovals) {
		return ApprovalCertificate{}, fmt.Errorf("decision: approval threshold is not satisfied")
	}
	sort.Strings(voteHashes)
	certificate := ApprovalCertificate{
		Version: SchemaVersion, TransactionHash: transactionHash,
		TenantID: transaction.TenantID, AgentID: transaction.AgentID,
		Outcome: transaction.Outcome, Constraints: append([]Constraint(nil), transaction.Constraints...),
		PolicyRevision: transaction.PolicyRevision, RevocationEpoch: transaction.RevocationEpoch,
		ApprovalVoteHashes: voteHashes, FinalizedAt: finalizedAt.Unix(), ExpiresAt: expiresAt,
		ProviderID: providerID, KeyID: keyID,
	}
	certificate.ID = approvalCertificateID(certificate)
	if err := certificate.Validate(); err != nil {
		return ApprovalCertificate{}, err
	}
	return certificate, nil
}

func (certificate ApprovalCertificate) Validate() error {
	if certificate.Version != SchemaVersion || !lowerHex(certificate.ID, 64) || !lowerHex(certificate.TransactionHash, 64) {
		return fmt.Errorf("decision: invalid approval certificate identity")
	}
	for name, value := range map[string]string{
		"tenant_id": certificate.TenantID, "agent_id": certificate.AgentID,
		"provider_id": certificate.ProviderID, "key_id": certificate.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if err := validateProposedAuthority(certificate.TenantID, certificate.AgentID, certificate.Outcome, certificate.Constraints); err != nil {
		return err
	}
	if certificate.PolicyRevision == 0 || certificate.FinalizedAt <= 0 || certificate.ExpiresAt <= certificate.FinalizedAt ||
		certificate.ExpiresAt-certificate.FinalizedAt > int64(MaxApprovalTransactionTTL/time.Second) ||
		len(certificate.ApprovalVoteHashes) == 0 || len(certificate.ApprovalVoteHashes) > MaxApprovalVotes {
		return fmt.Errorf("decision: invalid approval certificate state")
	}
	seen := make(map[string]struct{}, len(certificate.ApprovalVoteHashes))
	for _, hash := range certificate.ApprovalVoteHashes {
		if !lowerHex(hash, 64) {
			return fmt.Errorf("decision: invalid approval certificate vote hash")
		}
		if _, exists := seen[hash]; exists {
			return fmt.Errorf("decision: duplicate approval certificate vote hash")
		}
		seen[hash] = struct{}{}
	}
	if certificate.ID != approvalCertificateID(certificate) {
		return fmt.Errorf("decision: noncanonical approval certificate id")
	}
	return nil
}

func (certificate ApprovalCertificate) Canonical() ([]byte, error) {
	if err := certificate.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(ApprovalCertificateDomain)
	writer.u16(certificate.Version)
	writer.string(certificate.ID)
	writer.string(certificate.TransactionHash)
	writer.string(certificate.TenantID)
	writer.string(certificate.AgentID)
	writeProposedAuthority(&writer, certificate.Outcome, certificate.Constraints)
	writer.u64(certificate.PolicyRevision)
	writer.u64(certificate.RevocationEpoch)
	hashes := append([]string(nil), certificate.ApprovalVoteHashes...)
	sort.Strings(hashes)
	writer.u16(uint16(len(hashes)))
	for _, hash := range hashes {
		writer.string(hash)
	}
	writer.i64(certificate.FinalizedAt)
	writer.i64(certificate.ExpiresAt)
	writer.string(certificate.ProviderID)
	writer.string(certificate.KeyID)
	return writer.Bytes(), nil
}

func (certificate ApprovalCertificate) Hash() (string, error) {
	return hashCanonical(certificate.Canonical())
}

func (certificate *ApprovalCertificate) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid approval certificate private key")
	}
	return certificate.SignWith(func(message []byte) ([]byte, error) { return ed25519.Sign(privateKey, message), nil })
}

func (certificate *ApprovalCertificate) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := certificate.Canonical()
	if err != nil {
		return err
	}
	return setWorkflowSignature("approval certificate", &certificate.Signature, canonical, signer)
}

func (certificate ApprovalCertificate) VerifyFor(transaction ApprovalTransaction, votes []ApprovalVote, approvalKeys map[string]ed25519.PublicKey, decisionPublicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := certificate.Canonical()
	if err != nil {
		return err
	}
	if err := verifyFreshLong("approval certificate", certificate.FinalizedAt, certificate.ExpiresAt, now, MaxApprovalTransactionTTL); err != nil {
		return err
	}
	if err := verifySignature("approval certificate", decisionPublicKey, canonical, certificate.Signature); err != nil {
		return err
	}
	expected, err := approvalCertificateView(transaction, votes, approvalKeys, certificate.FinalizedAt)
	if err != nil {
		return err
	}
	if certificate.TransactionHash != expected.TransactionHash || certificate.TenantID != expected.TenantID || certificate.AgentID != expected.AgentID ||
		certificate.Outcome != expected.Outcome || !equalConstraints(certificate.Constraints, expected.Constraints) ||
		certificate.PolicyRevision != expected.PolicyRevision || certificate.RevocationEpoch != expected.RevocationEpoch ||
		certificate.ExpiresAt != expected.ExpiresAt || !equalStringsSorted(certificate.ApprovalVoteHashes, expected.ApprovalVoteHashes) {
		return fmt.Errorf("decision: approval certificate threshold binding mismatch")
	}
	return nil
}

// VerifyApprovedExecution binds a fresh workload-signed intent to a long-lived
// approval certificate. Callers must separately verify the intent signature
// and atomically consume the transaction before producing side effects.
func VerifyApprovedExecution(intent Intent, transaction ApprovalTransaction, certificate ApprovalCertificate, votes []ApprovalVote, approvalKeys map[string]ed25519.PublicKey, decisionPublicKey ed25519.PublicKey, now time.Time) error {
	if err := transaction.Verify(decisionPublicKey, now); err != nil {
		return err
	}
	if err := transaction.MatchesIntent(intent); err != nil {
		return err
	}
	if err := certificate.VerifyFor(transaction, votes, approvalKeys, decisionPublicKey, now); err != nil {
		return err
	}
	if intent.IssuedAt < certificate.FinalizedAt-int64(MaxClockSkew/time.Second) || intent.ExpiresAt > certificate.ExpiresAt {
		return fmt.Errorf("decision: execution intent is outside the approval certificate window")
	}
	return nil
}

func approvalCertificateView(transaction ApprovalTransaction, votes []ApprovalVote, approvalKeys map[string]ed25519.PublicKey, finalizedAt int64) (ApprovalCertificate, error) {
	if len(votes) == 0 || len(votes) > MaxApprovalVotes {
		return ApprovalCertificate{}, fmt.Errorf("decision: invalid approval vote count")
	}
	transactionHash, err := transaction.Hash()
	if err != nil {
		return ApprovalCertificate{}, err
	}
	seenKeys := make(map[string]struct{}, len(votes))
	var hashes []string
	expiresAt := transaction.ExpiresAt
	approved := 0
	for _, vote := range votes {
		key, exists := approvalKeys[vote.KeyID]
		if !exists {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval vote key is unavailable")
		}
		if err := vote.VerifyFor(transaction, key, time.Unix(finalizedAt, 0)); err != nil {
			return ApprovalCertificate{}, err
		}
		if _, exists := seenKeys[vote.KeyID]; exists {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval threshold repeats a key")
		}
		seenKeys[vote.KeyID] = struct{}{}
		if vote.Choice == ApprovalVoteReject {
			return ApprovalCertificate{}, fmt.Errorf("decision: approval transaction was rejected")
		}
		approved++
		if vote.ExpiresAt < expiresAt {
			expiresAt = vote.ExpiresAt
		}
		hash, _ := vote.Hash()
		hashes = append(hashes, hash)
	}
	if approved < int(transaction.RequiredApprovals) {
		return ApprovalCertificate{}, fmt.Errorf("decision: approval threshold is not satisfied")
	}
	sort.Strings(hashes)
	return ApprovalCertificate{
		TransactionHash: transactionHash, TenantID: transaction.TenantID, AgentID: transaction.AgentID,
		Outcome: transaction.Outcome, Constraints: append([]Constraint(nil), transaction.Constraints...),
		PolicyRevision: transaction.PolicyRevision, RevocationEpoch: transaction.RevocationEpoch,
		ApprovalVoteHashes: hashes, ExpiresAt: expiresAt,
	}, nil
}

func validateProposedAuthority(tenantID, agentID string, outcome Outcome, constraints []Constraint) error {
	probe := Decision{
		Version: SchemaVersion, ID: "approval-authority", IntentHash: "0000000000000000000000000000000000000000000000000000000000000000",
		TenantID: tenantID, AgentID: agentID, Outcome: outcome, Constraints: constraints,
		PolicyRevision: 1, ProviderID: "approval-authority", IssuedAt: 1, ExpiresAt: 2, KeyID: "approval-authority",
	}
	if outcome != Allow && outcome != Constrain {
		return fmt.Errorf("decision: approval transaction outcome must allow or constrain")
	}
	if err := probe.Validate(); err != nil {
		return err
	}
	return nil
}

func writeProposedAuthority(writer *canonicalWriter, outcome Outcome, constraints []Constraint) {
	writer.string(string(outcome))
	ordered := append([]Constraint(nil), constraints...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Key != ordered[j].Key {
			return ordered[i].Key < ordered[j].Key
		}
		if ordered[i].Operator != ordered[j].Operator {
			return ordered[i].Operator < ordered[j].Operator
		}
		return ordered[i].Value < ordered[j].Value
	})
	writer.u16(uint16(len(ordered)))
	for _, constraint := range ordered {
		writer.string(constraint.Key)
		writer.string(constraint.Operator)
		writer.string(constraint.Value)
	}
}

func approvalTransactionID(transaction ApprovalTransaction) string {
	writer := canonicalWriter{}
	writer.string(ApprovalTransactionDomain + "/id")
	writer.string(transaction.InitialDecisionHash)
	writer.string(transaction.TenantID)
	writer.string(transaction.AgentID)
	writer.string(transaction.Action)
	writer.string(transaction.Resource)
	writer.string(transaction.PayloadHash)
	writer.string(string(transaction.Risk))
	writeProposedAuthority(&writer, transaction.Outcome, transaction.Constraints)
	writer.u64(transaction.PolicyRevision)
	writer.u64(transaction.RevocationEpoch)
	keys := append([]string(nil), transaction.ApproverKeyIDs...)
	sort.Strings(keys)
	writer.u16(uint16(len(keys)))
	for _, keyID := range keys {
		writer.string(keyID)
	}
	writer.u16(transaction.RequiredApprovals)
	writer.i64(transaction.CreatedAt)
	writer.i64(transaction.ExpiresAt)
	writer.string(transaction.ProviderID)
	writer.string(transaction.KeyID)
	sum := sha256.Sum256(writer.Bytes())
	return hex.EncodeToString(sum[:])
}

func approvalVoteID(vote ApprovalVote) string {
	writer := canonicalWriter{}
	writer.string(ApprovalVoteDomain + "/id")
	writer.string(vote.TransactionHash)
	writer.string(vote.TenantID)
	writer.string(vote.ApproverID)
	writer.string(string(vote.Choice))
	writer.i64(vote.IssuedAt)
	writer.i64(vote.ExpiresAt)
	writer.string(vote.Nonce)
	writer.string(vote.KeyID)
	sum := sha256.Sum256(writer.Bytes())
	return hex.EncodeToString(sum[:])
}

func approvalCertificateID(certificate ApprovalCertificate) string {
	writer := canonicalWriter{}
	writer.string(ApprovalCertificateDomain + "/id")
	writer.string(certificate.TransactionHash)
	writer.string(certificate.TenantID)
	writer.string(certificate.AgentID)
	writeProposedAuthority(&writer, certificate.Outcome, certificate.Constraints)
	writer.u64(certificate.PolicyRevision)
	writer.u64(certificate.RevocationEpoch)
	hashes := append([]string(nil), certificate.ApprovalVoteHashes...)
	sort.Strings(hashes)
	writer.u16(uint16(len(hashes)))
	for _, hash := range hashes {
		writer.string(hash)
	}
	writer.i64(certificate.FinalizedAt)
	writer.i64(certificate.ExpiresAt)
	writer.string(certificate.ProviderID)
	writer.string(certificate.KeyID)
	sum := sha256.Sum256(writer.Bytes())
	return hex.EncodeToString(sum[:])
}

func verifyFreshLong(name string, issuedAt, expiresAt int64, now time.Time, maximum time.Duration) error {
	nowUnix := now.Unix()
	if issuedAt > nowUnix+int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: %s is from the future", name)
	}
	if expiresAt < nowUnix || expiresAt-issuedAt > int64(maximum/time.Second) {
		return fmt.Errorf("decision: %s is expired or exceeds its validity limit", name)
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStringsSorted(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func equalConstraints(left, right []Constraint) bool {
	if len(left) != len(right) {
		return false
	}
	a := append([]Constraint(nil), left...)
	b := append([]Constraint(nil), right...)
	order := func(values []Constraint) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].Key != values[j].Key {
				return values[i].Key < values[j].Key
			}
			if values[i].Operator != values[j].Operator {
				return values[i].Operator < values[j].Operator
			}
			return values[i].Value < values[j].Value
		})
	}
	order(a)
	order(b)
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func setWorkflowSignature(name string, target *string, canonical []byte, signer func([]byte) ([]byte, error)) error {
	if signer == nil {
		return fmt.Errorf("decision: %s signer is required", name)
	}
	signature, err := signer(canonical)
	if err != nil {
		return fmt.Errorf("decision: sign %s: %w", name, err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("decision: %s signer returned invalid signature length", name)
	}
	*target = base64.StdEncoding.EncodeToString(signature)
	return nil
}
