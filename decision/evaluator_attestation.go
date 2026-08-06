// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	EvaluatorAttestationVersion uint16 = 1
	EvaluatorAttestationDomain         = "pilot-evaluator-attestation-v1"
	MaxEvaluatorAttestationTTL         = 24 * time.Hour
)

// EvaluatorAttestation is a short-lived, independently signed assertion that
// an evaluator endpoint is approved for one residency. EvidenceHash binds an
// external attestation record without embedding operator or payload data in
// the control request.
type EvaluatorAttestation struct {
	Version      uint16 `json:"version"`
	Endpoint     string `json:"endpoint"`
	Residency    string `json:"residency"`
	AttestorID   string `json:"attestor_id"`
	EvidenceHash string `json:"evidence_hash"`
	IssuedAt     int64  `json:"issued_at"`
	ExpiresAt    int64  `json:"expires_at"`
	KeyID        string `json:"key_id"`
	Signature    string `json:"signature"`
}

func (attestation EvaluatorAttestation) Validate() error {
	if attestation.Version != EvaluatorAttestationVersion {
		return fmt.Errorf("decision: evaluator attestation version %d is unsupported", attestation.Version)
	}
	if _, err := canonicalEvaluatorEndpoint(attestation.Endpoint); err != nil {
		return err
	}
	if !validDisclosureResidency(attestation.Residency) {
		return fmt.Errorf("decision: invalid evaluator attestation residency %q", attestation.Residency)
	}
	for name, value := range map[string]string{"attestor_id": attestation.AttestorID, "key_id": attestation.KeyID} {
		if err := validateIdentifier(name, value); err != nil {
			return err
		}
	}
	if !lowerHex(attestation.EvidenceHash, 64) {
		return fmt.Errorf("decision: evaluator attestation evidence_hash must be 64 lowercase hex characters")
	}
	if err := validateWindow("evaluator attestation", attestation.IssuedAt, attestation.ExpiresAt, MaxEvaluatorAttestationTTL); err != nil {
		return err
	}
	return nil
}

func (attestation EvaluatorAttestation) Canonical() ([]byte, error) {
	if err := attestation.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := canonicalEvaluatorEndpoint(attestation.Endpoint)
	if err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	writer.string(EvaluatorAttestationDomain)
	writer.u16(attestation.Version)
	writer.string(endpoint)
	writer.string(attestation.Residency)
	writer.string(attestation.AttestorID)
	writer.string(attestation.EvidenceHash)
	writer.i64(attestation.IssuedAt)
	writer.i64(attestation.ExpiresAt)
	writer.string(attestation.KeyID)
	return writer.Bytes(), nil
}

func (attestation *EvaluatorAttestation) Sign(privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("decision: evaluator attestation signing key is invalid")
	}
	canonical, err := attestation.Canonical()
	if err != nil {
		return err
	}
	attestation.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return nil
}

// VerifyForEndpoint proves that a separately pinned attestor approved exactly
// this evaluator origin and residency at the current time.
func (attestation EvaluatorAttestation) VerifyForEndpoint(endpoint, residency, attestorID, keyID string, publicKey ed25519.PublicKey, now time.Time) error {
	if err := attestation.Validate(); err != nil {
		return err
	}
	expectedEndpoint, err := canonicalEvaluatorEndpoint(endpoint)
	if err != nil {
		return err
	}
	actualEndpoint, _ := canonicalEvaluatorEndpoint(attestation.Endpoint)
	if actualEndpoint != expectedEndpoint || attestation.Residency != residency || attestation.AttestorID != attestorID || attestation.KeyID != keyID {
		return fmt.Errorf("decision: evaluator attestation binding mismatch")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("decision: evaluator attestation public key is invalid")
	}
	if now.Unix() < attestation.IssuedAt-int64(MaxClockSkew/time.Second) || now.Unix() > attestation.ExpiresAt+int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("decision: evaluator attestation is outside its validity window")
	}
	canonical, err := attestation.Canonical()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(attestation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("decision: evaluator attestation signature is invalid")
	}
	return nil
}

func canonicalEvaluatorEndpoint(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("decision: evaluator attestation endpoint is invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("decision: evaluator attestation endpoint is invalid")
	}
	parsed.Path = ""
	parsed.RawPath = ""
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}
