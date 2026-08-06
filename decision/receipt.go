// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	ReceiptDomain            = "pilot-receipt-v1"
	ReceiptDisclosureDomain  = "pilot-receipt-v2"
	ReceiptDisclosureVersion = uint16(2)
)

type EnforcementResult string

const (
	Enforced        EnforcementResult = "enforced"
	Denied          EnforcementResult = "denied"
	ApprovalPending EnforcementResult = "approval_pending"
	Failed          EnforcementResult = "failed"
)

// Receipt is the signed local evidence that an enforcement point acted on a
// decision. Its deterministic ID is also the idempotency key for usage
// metering, so retrying delivery cannot create another billable unit.
type Receipt struct {
	Version      uint16 `json:"version"`
	ID           string `json:"id"`
	DecisionID   string `json:"decision_id"`
	DecisionHash string `json:"decision_hash"`
	IntentHash   string `json:"intent_hash"`
	// DisclosureHash is required only by receipt V2. It is the hash of the
	// canonical DisclosureBinding, never application plaintext.
	DisclosureHash string `json:"disclosure_hash,omitempty"`
	TenantID       string `json:"tenant_id"`
	MandateID      string `json:"mandate_id,omitempty"`
	// AgentID identifies the local enforcement agent whose delegated receipt
	// key signed this record. The initiating actor remains bound by IntentHash.
	AgentID          string            `json:"agent_id"`
	Outcome          Outcome           `json:"outcome"`
	Result           EnforcementResult `json:"result"`
	EnforcementPoint string            `json:"enforcement_point"`
	ObservedAt       int64             `json:"observed_at"`
	KeyID            string            `json:"key_id"`
	Signature        string            `json:"signature"`
}

func NewReceipt(intent Intent, result Decision, enforcementPoint, keyID string, observedAt int64, enforced EnforcementResult) (Receipt, error) {
	return NewReceiptForEnforcer(intent, result, intent.AgentID, enforcementPoint, keyID, observedAt, enforced)
}

// NewReceiptForEnforcer creates evidence for an enforcement point operated by
// enforcementAgentID. This differs from the Intent actor for receiver-side
// transport controls: a broker or inbox must sign with its own delegated
// receipt key, not with the sender's key. NewReceipt remains the convenient
// same-agent form used by wallets and local tools.
func NewReceiptForEnforcer(intent Intent, result Decision, enforcementAgentID, enforcementPoint, keyID string, observedAt int64, enforced EnforcementResult) (Receipt, error) {
	intentHash, err := intent.Hash()
	if err != nil {
		return Receipt{}, err
	}
	decisionHash, err := result.Hash()
	if err != nil {
		return Receipt{}, err
	}
	receiptID, err := ReceiptID(result.ID, enforcementPoint)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{
		Version:          SchemaVersion,
		ID:               receiptID,
		DecisionID:       result.ID,
		DecisionHash:     decisionHash,
		IntentHash:       intentHash,
		TenantID:         intent.TenantID,
		MandateID:        intent.MandateID,
		AgentID:          enforcementAgentID,
		Outcome:          result.Outcome,
		Result:           enforced,
		EnforcementPoint: enforcementPoint,
		ObservedAt:       observedAt,
		KeyID:            keyID,
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// NewDisclosureReceiptForEnforcer creates V2 enforcement evidence for a
// disclosure-bound action. V1 receipt canonical bytes and verification remain
// unchanged; V2 adds only the signed canonical disclosure hash.
func NewDisclosureReceiptForEnforcer(intent Intent, result Decision, disclosure DisclosureBinding, enforcementAgentID, enforcementPoint, keyID string, observedAt int64, enforced EnforcementResult) (Receipt, error) {
	if err := disclosure.VerifyIntent(intent); err != nil {
		return Receipt{}, err
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		return Receipt{}, err
	}
	receipt, err := NewReceiptForEnforcer(intent, result, enforcementAgentID, enforcementPoint, keyID, observedAt, enforced)
	if err != nil {
		return Receipt{}, err
	}
	receipt.Version = ReceiptDisclosureVersion
	receipt.DisclosureHash = disclosureHash
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func ReceiptID(decisionID, enforcementPoint string) (string, error) {
	if err := validateIdentifier("decision id", decisionID); err != nil {
		return "", err
	}
	if err := validateIdentifier("enforcement point", enforcementPoint); err != nil {
		return "", err
	}
	w := canonicalWriter{}
	w.string(ReceiptDomain + "/id")
	w.string(decisionID)
	w.string(enforcementPoint)
	sum := sha256.Sum256(w.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

func (r Receipt) UsageUnitID() string { return r.ID }

func (r Receipt) Validate() error {
	if r.Version != SchemaVersion && r.Version != ReceiptDisclosureVersion {
		return fmt.Errorf("decision: receipt version %d is unsupported", r.Version)
	}
	if r.Version == SchemaVersion && r.DisclosureHash != "" {
		return fmt.Errorf("decision: V1 receipt must not carry disclosure_hash")
	}
	if r.Version == ReceiptDisclosureVersion && !lowerHex(r.DisclosureHash, 64) {
		return fmt.Errorf("decision: V2 receipt requires disclosure_hash")
	}
	for name, value := range map[string]string{
		"decision id": r.DecisionID, "tenant_id": r.TenantID, "agent_id": r.AgentID,
		"enforcement point": r.EnforcementPoint, "key_id": r.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if r.MandateID != "" {
		if err := validateIdentifier("mandate_id", r.MandateID); err != nil {
			return err
		}
	}
	expectedID, err := ReceiptID(r.DecisionID, r.EnforcementPoint)
	if err != nil {
		return err
	}
	if r.ID != expectedID {
		return fmt.Errorf("decision: receipt id is not canonical for decision and enforcement point")
	}
	if !lowerHex(r.DecisionHash, 64) || !lowerHex(r.IntentHash, 64) {
		return fmt.Errorf("decision: receipt hashes must be 64 lowercase hex characters")
	}
	switch r.Outcome {
	case Allow, Deny, Constrain, ApprovalRequired:
	default:
		return fmt.Errorf("decision: invalid receipt outcome %q", r.Outcome)
	}
	switch r.Result {
	case Enforced, Denied, ApprovalPending, Failed:
	default:
		return fmt.Errorf("decision: invalid enforcement result %q", r.Result)
	}
	switch r.Outcome {
	case Deny:
		if r.Result != Denied {
			return fmt.Errorf("decision: deny outcome requires denied enforcement result")
		}
	case ApprovalRequired:
		if r.Result != ApprovalPending {
			return fmt.Errorf("decision: approval_required outcome requires approval_pending result")
		}
	case Allow, Constrain:
		if r.Result != Enforced && r.Result != Failed {
			return fmt.Errorf("decision: allow/constrain outcome requires enforced or failed result")
		}
	}
	if r.ObservedAt <= 0 {
		return fmt.Errorf("decision: invalid receipt observation time")
	}
	return nil
}

func (r Receipt) Canonical() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	domain := ReceiptDomain
	if r.Version == ReceiptDisclosureVersion {
		domain = ReceiptDisclosureDomain
	}
	if r.MandateID != "" {
		w.string(domain + "/delegated")
	} else {
		w.string(domain)
	}
	w.u16(r.Version)
	w.string(r.ID)
	w.string(r.DecisionID)
	w.string(r.DecisionHash)
	w.string(r.IntentHash)
	if r.Version == ReceiptDisclosureVersion {
		w.string(r.DisclosureHash)
	}
	w.string(r.TenantID)
	if r.MandateID != "" {
		w.string(r.MandateID)
	}
	w.string(r.AgentID)
	w.string(string(r.Outcome))
	w.string(string(r.Result))
	w.string(r.EnforcementPoint)
	w.i64(r.ObservedAt)
	w.string(r.KeyID)
	return w.Bytes(), nil
}

func (r Receipt) Hash() (string, error) { return hashCanonical(r.Canonical()) }

func (r *Receipt) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid receipt private key length")
	}
	return r.SignWith(func(message []byte) ([]byte, error) {
		return ed25519.Sign(privateKey, message), nil
	})
}

func (r *Receipt) SignWith(signer func([]byte) ([]byte, error)) error {
	if signer == nil {
		return fmt.Errorf("decision: receipt signer is required")
	}
	canonical, err := r.Canonical()
	if err != nil {
		return err
	}
	signature, err := signer(canonical)
	if err != nil {
		return fmt.Errorf("decision: sign receipt: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("decision: receipt signer returned invalid signature length")
	}
	r.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

func (r Receipt) Verify(publicKey ed25519.PublicKey) error {
	canonical, err := r.Canonical()
	if err != nil {
		return err
	}
	return verifySignature("receipt", publicKey, canonical, r.Signature)
}

func (r Receipt) VerifyFor(intent Intent, result Decision, publicKey ed25519.PublicKey) error {
	return r.VerifyForEnforcer(intent, result, intent.AgentID, publicKey)
}

// VerifyForEnforcer verifies evidence made by a particular enforcement agent.
// Callers resolve publicKey through the receipt-key delegation for that agent,
// while IntentHash and DecisionHash still bind the receipt to the original
// requesting actor and exact authority decision.
func (r Receipt) VerifyForEnforcer(intent Intent, result Decision, enforcementAgentID string, publicKey ed25519.PublicKey) error {
	if err := r.Verify(publicKey); err != nil {
		return err
	}
	intentHash, err := intent.Hash()
	if err != nil {
		return err
	}
	decisionHash, err := result.Hash()
	if err != nil {
		return err
	}
	if r.IntentHash != intentHash || r.DecisionHash != decisionHash || r.DecisionID != result.ID {
		return fmt.Errorf("decision: receipt object binding mismatch")
	}
	if r.TenantID != intent.TenantID || r.MandateID != intent.MandateID || r.AgentID != enforcementAgentID || r.Outcome != result.Outcome {
		return fmt.Errorf("decision: receipt authority binding mismatch")
	}
	return nil
}

// VerifyForDisclosure proves that V2 evidence was signed for this exact
// disclosure binding in addition to the Intent and Decision it already binds.
func (r Receipt) VerifyForDisclosure(intent Intent, result Decision, disclosure DisclosureBinding, enforcementAgentID string, publicKey ed25519.PublicKey) error {
	if r.Version != ReceiptDisclosureVersion {
		return fmt.Errorf("decision: disclosure evidence requires a V2 receipt")
	}
	if err := disclosure.VerifyIntent(intent); err != nil {
		return err
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		return err
	}
	if r.DisclosureHash != disclosureHash {
		return fmt.Errorf("decision: receipt disclosure binding mismatch")
	}
	return r.VerifyForEnforcer(intent, result, enforcementAgentID, publicKey)
}
