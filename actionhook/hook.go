// SPDX-License-Identifier: AGPL-3.0-or-later

// Package actionhook defines Pilot's versioned before/after side-effect
// boundary. It is deliberately optional: a nil Hook means the application
// executes exactly as it did before governance was attached.
package actionhook

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/decision"
)

const SchemaVersion uint16 = 1

const (
	MaxAttributes     = 32
	MaxAttributeValue = 256
)

// Envelope is evaluated before an adapter performs a side effect. Ordinary
// local/observe hooks use only PayloadHash. A managed hosted-federation hook
// may additionally carry FederatedContent to Pilot's account ingress.
// Attributes remain typed call metadata rather than an alternative channel
// for content, secrets, local paths, or peer network addresses.
type Envelope struct {
	Version     uint16            `json:"version"`
	ID          string            `json:"id"`
	Action      string            `json:"action"`
	Resource    string            `json:"resource"`
	PayloadHash string            `json:"payload_hash"`
	AdapterID   string            `json:"adapter_id"`
	CreatedAt   int64             `json:"created_at"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	// FederatedContent is the complete request body submitted to Pilot's
	// hosted account ingress in managed mode. It is process-local hook input:
	// envelope JSON, traces, continuations, and receipts never serialize it.
	FederatedContent *decision.FederatedContent `json:"-"`
	// ResumeToken is adapter-local state used to find a durable continuation.
	// It is deliberately excluded from JSON and never sent to an evaluator.
	ResumeToken string `json:"-"`
}

// DecisionReference is safe to persist in an action trace. It contains no
// provider request body and no opaque adapter resume state.
type DecisionReference struct {
	IntentID            string `json:"intent_id,omitempty"`
	DecisionID          string `json:"decision_id,omitempty"`
	ExchangeID          string `json:"exchange_id,omitempty"`
	PolicyRevision      uint64 `json:"policy_revision,omitempty"`
	ProviderID          string `json:"provider_id,omitempty"`
	ApprovalTransaction string `json:"approval_transaction_id,omitempty"`
	ApprovalExpiresAt   int64  `json:"approval_expires_at,omitempty"`
}

// Preflight is the hook's answer. State is process-local opaque state used by
// the same Hook during AfterAction; it is never serialized or accepted from a
// caller. ObserveOnly makes the result evidentiary and never blocking.
type Preflight struct {
	Outcome     decision.Outcome      `json:"outcome"`
	Reasons     []string              `json:"reasons,omitempty"`
	Constraints []decision.Constraint `json:"constraints,omitempty"`
	Reference   DecisionReference     `json:"reference,omitempty"`
	ObserveOnly bool                  `json:"observe_only,omitempty"`
	State       any                   `json:"-"`
}

type ObservedStatus string

const (
	StatusSucceeded       ObservedStatus = "succeeded"
	StatusFailed          ObservedStatus = "failed"
	StatusSkipped         ObservedStatus = "skipped"
	StatusDenied          ObservedStatus = "denied"
	StatusApprovalPending ObservedStatus = "approval_pending"
)

// ObservedResult records what actually happened after preflight. ErrorCode is
// a bounded category, never an arbitrary error string that could leak data.
type ObservedResult struct {
	Status     ObservedStatus    `json:"status"`
	ObservedAt int64             `json:"observed_at"`
	ErrorCode  string            `json:"error_code,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// FederatedContent is an optional complete response or returned artifact
	// for the Pilot-hosted post-hook. Like request content, it is process-local
	// and is never serialized into traces or local receipts.
	FederatedContent *decision.FederatedContent `json:"-"`
}

// Hook is the universal optional side-effect boundary. AfterAction is
// evidence-only: its failure must be surfaced to telemetry, but it cannot
// retroactively change or repeat the adapter side effect.
type Hook interface {
	BeforeAction(context.Context, Envelope) (Preflight, error)
	AfterAction(context.Context, Envelope, Preflight, ObservedResult) error
}

// BlockedError is returned by RequireUnconstrained when a valid preflight does
// not authorize the adapter to execute immediately.
type BlockedError struct {
	Outcome   decision.Outcome
	Reference DecisionReference
	Reasons   []string
}

func (err *BlockedError) Error() string {
	switch err.Outcome {
	case decision.Deny:
		return "actionhook: action denied"
	case decision.ApprovalRequired:
		if err.Reference.ApprovalTransaction != "" {
			return fmt.Sprintf("actionhook: action requires approval transaction %s", err.Reference.ApprovalTransaction)
		}
		return "actionhook: action requires approval"
	case decision.Constrain:
		return "actionhook: adapter cannot enforce returned constraints"
	default:
		return fmt.Sprintf("actionhook: action is not executable (%s)", err.Outcome)
	}
}

// RequireUnconstrained is the safe execution check for adapters that do not
// implement constraint operators. Observe-only hooks never block execution.
func (preflight Preflight) RequireUnconstrained() error {
	if preflight.ObserveOnly {
		return nil
	}
	switch preflight.Outcome {
	case decision.Allow:
		if len(preflight.Constraints) != 0 {
			return &BlockedError{Outcome: decision.Constrain, Reference: preflight.Reference, Reasons: append([]string(nil), preflight.Reasons...)}
		}
		return nil
	case decision.Constrain, decision.Deny, decision.ApprovalRequired:
		return &BlockedError{Outcome: preflight.Outcome, Reference: preflight.Reference, Reasons: append([]string(nil), preflight.Reasons...)}
	default:
		return fmt.Errorf("actionhook: invalid preflight outcome %q", preflight.Outcome)
	}
}

func NewEnvelope(action, resource, payloadHash, adapterID string, attributes map[string]string, now time.Time) (Envelope, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Envelope{}, fmt.Errorf("actionhook: generate action id: %w", err)
	}
	envelope := Envelope{
		Version: SchemaVersion, ID: "action-" + hex.EncodeToString(nonce[:]),
		Action: action, Resource: resource, PayloadHash: payloadHash,
		AdapterID: adapterID, CreatedAt: now.UTC().Unix(), Attributes: cloneAttributes(attributes),
	}
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func NewFederatedEnvelope(action, resource, adapterID string, content decision.FederatedContent, attributes map[string]string, now time.Time) (Envelope, error) {
	if err := content.Validate(); err != nil {
		return Envelope{}, err
	}
	payloadHash, err := content.Disclosure.Hash()
	if err != nil {
		return Envelope{}, err
	}
	envelope, err := NewEnvelope(action, resource, payloadHash, adapterID, attributes, now)
	if err != nil {
		return Envelope{}, err
	}
	cloned := content.Clone()
	envelope.FederatedContent = &cloned
	if err := envelope.Validate(); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func (envelope Envelope) Validate() error {
	if envelope.Version != SchemaVersion {
		return fmt.Errorf("actionhook: unsupported envelope version %d", envelope.Version)
	}
	if !validIdentifier(envelope.ID, 128) || !validDottedName(envelope.Action) || !validIdentifier(envelope.AdapterID, 128) {
		return fmt.Errorf("actionhook: invalid action, adapter, or envelope identity")
	}
	if !validText(envelope.Resource, 1024) {
		return fmt.Errorf("actionhook: invalid resource")
	}
	if len(envelope.PayloadHash) != sha256.Size*2 {
		return fmt.Errorf("actionhook: payload hash must be SHA-256")
	}
	if _, err := hex.DecodeString(envelope.PayloadHash); err != nil || envelope.PayloadHash != strings.ToLower(envelope.PayloadHash) {
		return fmt.Errorf("actionhook: payload hash must be lowercase hexadecimal")
	}
	if envelope.CreatedAt <= 0 {
		return fmt.Errorf("actionhook: invalid creation time")
	}
	if envelope.FederatedContent != nil {
		if err := envelope.FederatedContent.Validate(); err != nil {
			return err
		}
		bindingHash, err := envelope.FederatedContent.Disclosure.Hash()
		if err != nil || bindingHash != envelope.PayloadHash {
			return fmt.Errorf("actionhook: federated content does not match payload hash")
		}
	}
	if !validTextAllowEmpty(envelope.ResumeToken, 1024) {
		return fmt.Errorf("actionhook: invalid local resume token")
	}
	return validateAttributes(envelope.Attributes)
}

func (result ObservedResult) Validate() error {
	switch result.Status {
	case StatusSucceeded, StatusFailed, StatusSkipped, StatusDenied, StatusApprovalPending:
	default:
		return fmt.Errorf("actionhook: invalid observed status %q", result.Status)
	}
	if result.ObservedAt <= 0 || (result.ErrorCode != "" && !validIdentifier(result.ErrorCode, 128)) {
		return fmt.Errorf("actionhook: invalid observed result")
	}
	if result.FederatedContent != nil {
		if err := result.FederatedContent.Validate(); err != nil {
			return err
		}
	}
	return validateAttributes(result.Attributes)
}

// HashMetadata creates the payload binding for actions whose policy context is
// entirely metadata. Length-prefixing and sorting prevent ambiguous joins.
func HashMetadata(values map[string]string) string {
	hash := sha256.New()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeHashPart(hash, key)
		writeHashPart(hash, values[key])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func writeHashPart(hash interface{ Write([]byte) (int, error) }, value string) {
	length := uint64(len(value))
	var encoded [8]byte
	for index := 7; index >= 0; index-- {
		encoded[index] = byte(length)
		length >>= 8
	}
	_, _ = hash.Write(encoded[:])
	_, _ = hash.Write([]byte(value))
}

func validateAttributes(attributes map[string]string) error {
	if len(attributes) > MaxAttributes {
		return fmt.Errorf("actionhook: at most %d attributes are allowed", MaxAttributes)
	}
	for key, value := range attributes {
		if !validIdentifier(key, 64) || !validTextAllowEmpty(value, MaxAttributeValue) {
			return fmt.Errorf("actionhook: invalid attribute %q", key)
		}
	}
	return nil
}

func cloneAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	clone := make(map[string]string, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

func validIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func validDottedName(value string) bool {
	return strings.Contains(value, ".") && validIdentifier(value, 128) && value == strings.ToLower(value)
}

func validText(value string, max int) bool { return value != "" && validTextAllowEmpty(value, max) }

func validTextAllowEmpty(value string, max int) bool {
	if len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
