// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	FederationResultVersion uint16 = 1
	FederationResultDomain         = "pilot-federation-result-v1"
)

type FederationResultStatus string

const (
	FederationResultSucceeded       FederationResultStatus = "succeeded"
	FederationResultFailed          FederationResultStatus = "failed"
	FederationResultSkipped         FederationResultStatus = "skipped"
	FederationResultDenied          FederationResultStatus = "denied"
	FederationResultApprovalPending FederationResultStatus = "approval_pending"
)

// FederationResult is the enrolled node's signed post-hook assertion for one
// hosted exchange. IntentHash and DecisionID bind the exact authorization that
// preceded execution. ResponseDisclosureHash, when present, binds the complete
// response content carried beside this object without placing plaintext in
// logs, receipts, or command telemetry.
type FederationResult struct {
	Version                uint16                 `json:"version"`
	ID                     string                 `json:"id"`
	ExchangeID             string                 `json:"exchange_id"`
	TenantID               string                 `json:"tenant_id"`
	AgentID                string                 `json:"agent_id"`
	IntentHash             string                 `json:"intent_hash"`
	DecisionID             string                 `json:"decision_id"`
	Status                 FederationResultStatus `json:"status"`
	ErrorCode              string                 `json:"error_code,omitempty"`
	ResponseDisclosureHash string                 `json:"response_disclosure_hash,omitempty"`
	ObservedAt             int64                  `json:"observed_at"`
	KeyID                  string                 `json:"key_id"`
	Signature              string                 `json:"signature"`
}

func NewFederationResult(exchangeID string, intent Intent, result Decision, status FederationResultStatus, errorCode string, response *DisclosureBinding, observedAt time.Time, keyID string) (FederationResult, error) {
	intentHash, err := intent.Hash()
	if err != nil {
		return FederationResult{}, err
	}
	responseHash := ""
	if response != nil {
		responseHash, err = response.Hash()
		if err != nil {
			return FederationResult{}, err
		}
	}
	record := FederationResult{
		Version: FederationResultVersion, ExchangeID: exchangeID,
		TenantID: intent.TenantID, AgentID: intent.AgentID, IntentHash: intentHash,
		DecisionID: result.ID, Status: status, ErrorCode: errorCode,
		ResponseDisclosureHash: responseHash, ObservedAt: observedAt.UTC().Unix(), KeyID: keyID,
	}
	digest := sha256.Sum256([]byte(FederationResultDomain + "\x00" + exchangeID + "\x00" + intentHash + "\x00" + result.ID + "\x00" + string(status) + "\x00" + fmt.Sprint(record.ObservedAt) + "\x00" + responseHash))
	record.ID = "result-" + hex.EncodeToString(digest[:16])
	if err := record.Validate(); err != nil {
		return FederationResult{}, err
	}
	return record, nil
}

func (result FederationResult) Validate() error {
	if result.Version != FederationResultVersion {
		return fmt.Errorf("decision: unsupported federation result version")
	}
	for name, value := range map[string]string{
		"id": result.ID, "exchange_id": result.ExchangeID, "tenant_id": result.TenantID,
		"agent_id": result.AgentID, "decision_id": result.DecisionID, "key_id": result.KeyID,
	} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !lowerHex(result.IntentHash, 64) || result.ResponseDisclosureHash != "" && !lowerHex(result.ResponseDisclosureHash, 64) {
		return fmt.Errorf("decision: invalid federation result hash binding")
	}
	switch result.Status {
	case FederationResultSucceeded:
		if result.ErrorCode != "" {
			return fmt.Errorf("decision: successful federation result has an error code")
		}
	case FederationResultFailed:
		if err := validateIdentifier("error_code", result.ErrorCode); err != nil {
			return err
		}
	case FederationResultSkipped, FederationResultDenied, FederationResultApprovalPending:
		if result.ErrorCode != "" {
			if err := validateIdentifier("error_code", result.ErrorCode); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("decision: invalid federation result status %q", result.Status)
	}
	if result.ObservedAt <= 0 {
		return fmt.Errorf("decision: invalid federation result observation time")
	}
	return nil
}

func (result FederationResult) Canonical() ([]byte, error) {
	if err := result.Validate(); err != nil {
		return nil, err
	}
	w := canonicalWriter{}
	w.string(FederationResultDomain)
	w.u16(result.Version)
	w.string(result.ID)
	w.string(result.ExchangeID)
	w.string(result.TenantID)
	w.string(result.AgentID)
	w.string(result.IntentHash)
	w.string(result.DecisionID)
	w.string(string(result.Status))
	w.string(result.ErrorCode)
	w.string(result.ResponseDisclosureHash)
	w.i64(result.ObservedAt)
	w.string(result.KeyID)
	return w.Bytes(), nil
}

func (result *FederationResult) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: invalid federation result signing key")
	}
	canonical, err := result.Canonical()
	if err != nil {
		return err
	}
	result.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

func (result FederationResult) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	canonical, err := result.Canonical()
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || result.ObservedAt > now.Unix()+int64(MaxClockSkew/time.Second) || result.ObservedAt < now.Add(-24*time.Hour).Unix() {
		return fmt.Errorf("decision: federation result is outside its accepted observation window")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("decision: invalid federation result signature")
	}
	return nil
}
