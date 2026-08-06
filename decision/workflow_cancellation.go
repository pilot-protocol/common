// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

const ApprovalCancellationDomain = "pilot-approval-cancellation-v1"

// ApprovalCancellation is a decision-authority-signed terminal transition for
// an unconsumed approval transaction. It gives operators durable evidence that
// an approval was deliberately stopped rather than merely left to expire.
type ApprovalCancellation struct {
	Version         uint16 `json:"version"`
	ID              string `json:"id"`
	TransactionHash string `json:"transaction_hash"`
	TenantID        string `json:"tenant_id"`
	Reason          string `json:"reason"`
	CancelledAt     int64  `json:"cancelled_at"`
	ProviderID      string `json:"provider_id"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

func NewApprovalCancellation(transaction ApprovalTransaction, reason string, cancelledAt time.Time, providerID, keyID string) (ApprovalCancellation, error) {
	transactionHash, err := transaction.Hash()
	if err != nil {
		return ApprovalCancellation{}, err
	}
	cancellation := ApprovalCancellation{
		Version: SchemaVersion, TransactionHash: transactionHash, TenantID: transaction.TenantID,
		Reason: reason, CancelledAt: cancelledAt.Unix(), ProviderID: providerID, KeyID: keyID,
	}
	cancellation.ID = approvalCancellationID(cancellation)
	if err := cancellation.Validate(); err != nil {
		return ApprovalCancellation{}, err
	}
	return cancellation, nil
}

func (cancellation ApprovalCancellation) Validate() error {
	if cancellation.Version != SchemaVersion || !lowerHex(cancellation.ID, 64) || !lowerHex(cancellation.TransactionHash, 64) {
		return fmt.Errorf("decision: invalid approval cancellation identity")
	}
	for name, value := range map[string]string{
		"tenant_id": cancellation.TenantID, "provider_id": cancellation.ProviderID, "key_id": cancellation.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if err := validateText("reason", cancellation.Reason, 512, false); err != nil {
		return err
	}
	if cancellation.CancelledAt <= 0 || cancellation.ID != approvalCancellationID(cancellation) {
		return fmt.Errorf("decision: invalid approval cancellation state")
	}
	return nil
}

func (cancellation ApprovalCancellation) Canonical() ([]byte, error) {
	if err := cancellation.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(ApprovalCancellationDomain)
	writer.u16(cancellation.Version)
	writer.string(cancellation.ID)
	writer.string(cancellation.TransactionHash)
	writer.string(cancellation.TenantID)
	writer.string(cancellation.Reason)
	writer.i64(cancellation.CancelledAt)
	writer.string(cancellation.ProviderID)
	writer.string(cancellation.KeyID)
	return writer.Bytes(), nil
}

func (cancellation ApprovalCancellation) Hash() (string, error) {
	return hashCanonical(cancellation.Canonical())
}

func (cancellation *ApprovalCancellation) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid approval cancellation private key")
	}
	return cancellation.SignWith(func(message []byte) ([]byte, error) { return ed25519.Sign(privateKey, message), nil })
}

func (cancellation *ApprovalCancellation) SignWith(signer func([]byte) ([]byte, error)) error {
	canonical, err := cancellation.Canonical()
	if err != nil {
		return err
	}
	return setWorkflowSignature("approval cancellation", &cancellation.Signature, canonical, signer)
}

func (cancellation ApprovalCancellation) VerifyFor(transaction ApprovalTransaction, decisionPublicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := cancellation.Canonical()
	if err != nil {
		return err
	}
	transactionHash, err := transaction.Hash()
	if err != nil || cancellation.TransactionHash != transactionHash || cancellation.TenantID != transaction.TenantID {
		return fmt.Errorf("decision: approval cancellation transaction binding mismatch")
	}
	if cancellation.CancelledAt > now.Unix()+int64(MaxClockSkew/time.Second) || cancellation.CancelledAt < now.Unix()-int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: approval cancellation is not fresh")
	}
	return verifySignature("approval cancellation", decisionPublicKey, canonical, cancellation.Signature)
}

func approvalCancellationID(cancellation ApprovalCancellation) string {
	writer := canonicalWriter{}
	writer.string(ApprovalCancellationDomain + "/id")
	writer.string(cancellation.TransactionHash)
	writer.string(cancellation.TenantID)
	writer.string(cancellation.Reason)
	writer.i64(cancellation.CancelledAt)
	writer.string(cancellation.ProviderID)
	writer.string(cancellation.KeyID)
	sum := sha256.Sum256(writer.Bytes())
	return hex.EncodeToString(sum[:])
}
