// SPDX-License-Identifier: AGPL-3.0-or-later

package badgeverify

import (
	"fmt"
	"strings"
	"time"
)

// This file adds the two registry-facing credential types that share the
// badge's signing primitive and keyring but carry distinct domain-
// separation prefixes (see badgeverify.go):
//
//   - Enrollment: signed by the BADGE-issuer key, records the durable
//     address -> identity-commitment binding that recovery later matches.
//   - Recovery:   signed by the COLD RECOVERY-authority key (a different
//     kid), authorizes force-rotating an address to a new key. It MUST be
//     single-use (nonce, tracked by the registry) and short-lived (exp).
//
// Apps never handle these — only the registry (and the verifier, which
// produces them) does.

// Enrollment binds an address to a salted identity commitment. The raw
// external identity is never present; Commitment is HMAC(verifier_salt,
// external_id), opaque to everyone but the verifier.
type Enrollment struct {
	NodeID     uint32
	Provider   string
	Commitment string // base64/hex HMAC; never the raw identity
	IssuedAt   int64
	Kid        string
}

// Recovery authorizes rotating NodeID to NewPubKey because the enrolled
// identity (Commitment) was re-proven. NewPubKey is bound into the signed
// bytes, so an intercepted authorization is useless to anyone who does not
// hold NewPubKey's private key.
type Recovery struct {
	NodeID     uint32
	NewPubKey  string // base64 Ed25519 public key the address rotates to
	Commitment string
	Exp        int64  // unix seconds; MUST be non-zero and is enforced
	Nonce      string // single-use; the registry rejects replays
	Kid        string
}

// CanonicalEnrollment builds the signed bytes for an enrollment.
// Layout: pilotenroll:v1:<node_id>:<provider>:<commitment>:<issued_at>:<kid>
func CanonicalEnrollment(e Enrollment) (string, error) {
	for _, c := range []struct{ name, v string }{
		{"provider", e.Provider}, {"commitment", e.Commitment}, {"kid", e.Kid},
	} {
		if c.v == "" {
			return "", fmt.Errorf("%w: enrollment %s is required", ErrMalformed, c.name)
		}
		if err := noColon(c.name, c.v); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s:%s:%d:%s:%s:%d:%s",
		prefixEnroll, Version, e.NodeID, e.Provider, e.Commitment, e.IssuedAt, e.Kid), nil
}

// CanonicalRecovery builds the signed bytes for a recovery authorization.
// Layout: pilotrecover:v1:<node_id>:<new_pubkey>:<commitment>:<exp>:<nonce>:<kid>
//
// Exp must be non-zero: a recovery authorization that never expires would
// be a permanent, replayable takeover token.
func CanonicalRecovery(r Recovery) (string, error) {
	if r.Exp <= 0 {
		return "", fmt.Errorf("%w: recovery exp must be set (non-zero)", ErrMalformed)
	}
	for _, c := range []struct{ name, v string }{
		{"new_pubkey", r.NewPubKey}, {"commitment", r.Commitment}, {"nonce", r.Nonce}, {"kid", r.Kid},
	} {
		if c.v == "" {
			return "", fmt.Errorf("%w: recovery %s is required", ErrMalformed, c.name)
		}
		if err := noColon(c.name, c.v); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s:%s:%d:%s:%s:%d:%s:%s",
		prefixRecover, Version, r.NodeID, r.NewPubKey, r.Commitment, r.Exp, r.Nonce, r.Kid), nil
}

// ParseEnrollment decodes an enrollment string WITHOUT verifying its
// signature. It rejects any non-enrollment prefix (domain separation).
func ParseEnrollment(s string) (Enrollment, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 7 {
		return Enrollment{}, fmt.Errorf("%w: enrollment wants 7 fields, got %d", ErrMalformed, len(parts))
	}
	if parts[0] != prefixEnroll {
		return Enrollment{}, fmt.Errorf("%w: not an enrollment (prefix %q)", ErrMalformed, parts[0])
	}
	if parts[1] != Version {
		return Enrollment{}, fmt.Errorf("%w: unsupported version %q", ErrMalformed, parts[1])
	}
	nodeID, err := parseCanonicalUint32("node_id", parts[2])
	if err != nil {
		return Enrollment{}, err
	}
	issuedAt, err := parseCanonicalInt64("issued_at", parts[5])
	if err != nil {
		return Enrollment{}, err
	}
	if parts[3] == "" || parts[4] == "" || parts[6] == "" {
		return Enrollment{}, fmt.Errorf("%w: enrollment has empty required field", ErrMalformed)
	}
	return Enrollment{
		NodeID: nodeID, Provider: parts[3], Commitment: parts[4],
		IssuedAt: issuedAt, Kid: parts[6],
	}, nil
}

// ParseRecovery decodes a recovery string WITHOUT verifying its signature.
// It rejects any non-recovery prefix (domain separation).
func ParseRecovery(s string) (Recovery, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 8 {
		return Recovery{}, fmt.Errorf("%w: recovery wants 8 fields, got %d", ErrMalformed, len(parts))
	}
	if parts[0] != prefixRecover {
		return Recovery{}, fmt.Errorf("%w: not a recovery (prefix %q)", ErrMalformed, parts[0])
	}
	if parts[1] != Version {
		return Recovery{}, fmt.Errorf("%w: unsupported version %q", ErrMalformed, parts[1])
	}
	nodeID, err := parseCanonicalUint32("node_id", parts[2])
	if err != nil {
		return Recovery{}, err
	}
	exp, err := parseCanonicalInt64("exp", parts[5])
	if err != nil {
		return Recovery{}, err
	}
	// A recovery with exp<=0 is never valid (CanonicalRecovery refuses to
	// emit one); reject it at the parse boundary so the round-trip is exact
	// and an exp=0 takeover token cannot even be represented.
	if exp <= 0 {
		return Recovery{}, fmt.Errorf("%w: recovery exp must be set (non-zero)", ErrMalformed)
	}
	if parts[3] == "" || parts[4] == "" || parts[6] == "" || parts[7] == "" {
		return Recovery{}, fmt.Errorf("%w: recovery has empty required field", ErrMalformed)
	}
	return Recovery{
		NodeID: nodeID, NewPubKey: parts[3], Commitment: parts[4],
		Exp: exp, Nonce: parts[6], Kid: parts[7],
	}, nil
}

// VerifyEnrollment checks the signature of an enrollment against the pinned
// key named by its kid.
func VerifyEnrollment(s, sigB64 string) (Enrollment, error) {
	e, err := ParseEnrollment(s)
	if err != nil {
		return Enrollment{}, err
	}
	if err := verifyDetached(s, sigB64, e.Kid); err != nil {
		return e, err
	}
	return e, nil
}

// VerifyRecovery checks a recovery authorization: signature against the
// pinned (cold recovery-authority) key named by its kid, AND that it has
// not expired. The caller (registry) MUST additionally enforce single-use
// of Nonce and that Commitment matches the address's enrolled commitment.
func VerifyRecovery(s, sigB64 string) (Recovery, error) {
	return verifyRecoveryAt(s, sigB64, time.Now())
}

func verifyRecoveryAt(s, sigB64 string, now time.Time) (Recovery, error) {
	r, err := ParseRecovery(s)
	if err != nil {
		return Recovery{}, err
	}
	if r.Exp <= 0 {
		return r, fmt.Errorf("%w: recovery exp must be non-zero", ErrMalformed)
	}
	// Recovery verifies ONLY against the cold recovery keyring — never the
	// online badge keyring — so a compromised badge key cannot forge one.
	if err := verifyDetachedRecovery(s, sigB64, r.Kid); err != nil {
		return r, err
	}
	if now.Unix() > r.Exp {
		return r, fmt.Errorf("%w: exp=%d now=%d", ErrExpired, r.Exp, now.Unix())
	}
	return r, nil
}
