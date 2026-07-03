// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reqsig implements the canonical request-signature envelope used to
// prove that a request originates from a registered Pilot node, and the
// registry-signed verdict returned by verification endpoints.
//
// Envelope canonical form (all fields fixed-charset so '|' can never occur
// inside a field):
//
//	pilot-req-v1|aaaaaaaaaaaa|ts|nnnnnnnnnnnnnnnn|hhhh…64…hhhh|audience
//
//	aaaa…       12 lowercase hex chars: 4 for the 16-bit network,
//	            8 for the 32-bit node ID (the Pilot address, no separators —
//	            the text address format "N:NNNN.HHHH.LLLL" contains ':' and
//	            '.' and is deliberately NOT used here)
//	ts          canonical decimal unix seconds (no sign, no leading zeros)
//	nonce       16 lowercase hex chars (8 random bytes)
//	body hash   64 lowercase hex chars, sha256 of the request body
//	audience    [a-z0-9.-]{1,64}, the consuming service's identifier
//
// The domain prefix provides domain separation: a signature over an envelope
// can never be confused with a protocol-internal signature (heartbeats, key
// exchange, badges), and signers MUST refuse to sign anything that is not a
// well-formed envelope naming their own address.
//
// Freshness: verifiers reject envelopes whose timestamp is outside a skew
// window (DefaultMaxSkew). Nonce dedup within the window is the consuming
// service's responsibility; the registry echoes the nonce in its verdict so
// services can key a dedup cache on it.
package reqsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// Domain is the envelope domain-separation prefix.
	Domain = "pilot-req-v1"

	// DefaultMaxSkew is the default freshness window for envelope
	// timestamps. Deliberately generous: the fleet includes embedded
	// devices and NAT'd VMs with real clock skew, and replay within the
	// window is bounded by the consumer's nonce dedup.
	DefaultMaxSkew = 300 * time.Second

	// NonceLen is the hex length of an envelope nonce (8 random bytes).
	NonceLen = 16

	fieldCount = 6
)

// Envelope is a parsed request-signature envelope.
type Envelope struct {
	Network   uint16
	Node      uint32
	Timestamp int64  // unix seconds
	Nonce     string // 16 lowercase hex chars
	BodyHash  string // 64 lowercase hex chars (sha256 of body)
	Audience  string // [a-z0-9.-]{1,64}
}

// HashBody returns the canonical body-hash field for a request body.
func HashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// NewNonce returns a fresh random envelope nonce.
func NewNonce() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("reqsig: nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Canonical validates the envelope fields and returns the canonical string.
func (e Envelope) Canonical() (string, error) {
	if e.Timestamp < 0 {
		return "", fmt.Errorf("reqsig: negative timestamp")
	}
	if !isLowerHex(e.Nonce, NonceLen) {
		return "", fmt.Errorf("reqsig: nonce must be %d lowercase hex chars", NonceLen)
	}
	if !isLowerHex(e.BodyHash, 64) {
		return "", fmt.Errorf("reqsig: body hash must be 64 lowercase hex chars")
	}
	if err := checkAudience(e.Audience); err != nil {
		return "", err
	}
	return Domain + "|" +
		addrHex(e.Network, e.Node) + "|" +
		strconv.FormatInt(e.Timestamp, 10) + "|" +
		e.Nonce + "|" +
		e.BodyHash + "|" +
		e.Audience, nil
}

// Parse parses and validates a canonical envelope string.
func Parse(s string) (Envelope, error) {
	parts := strings.Split(s, "|")
	if len(parts) != fieldCount {
		return Envelope{}, fmt.Errorf("reqsig: want %d fields, got %d", fieldCount, len(parts))
	}
	if parts[0] != Domain {
		return Envelope{}, fmt.Errorf("reqsig: bad domain %q", parts[0])
	}
	network, node, err := parseAddrHex(parts[1])
	if err != nil {
		return Envelope{}, err
	}
	ts, err := parseCanonicalDecimal(parts[2])
	if err != nil {
		return Envelope{}, fmt.Errorf("reqsig: timestamp: %w", err)
	}
	e := Envelope{
		Network:   network,
		Node:      node,
		Timestamp: ts,
		Nonce:     parts[3],
		BodyHash:  parts[4],
		Audience:  parts[5],
	}
	// Round-trip through Canonical so every field-level rule is enforced
	// on the parse path too, and the accepted string is bit-identical to
	// what Canonical would produce.
	canon, err := e.Canonical()
	if err != nil {
		return Envelope{}, err
	}
	if canon != s {
		return Envelope{}, fmt.Errorf("reqsig: non-canonical encoding")
	}
	return e, nil
}

// Sign validates the envelope, builds its canonical form, and signs it.
// Returns the canonical string and the base64 signature.
func Sign(priv ed25519.PrivateKey, e Envelope) (canonical, sigB64 string, err error) {
	canonical, err = e.Canonical()
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	return canonical, base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks sigB64 over the canonical envelope string with pub and
// returns the parsed envelope. It performs NO freshness check — callers
// combine it with CheckFresh.
func Verify(pub ed25519.PublicKey, canonical, sigB64 string) (Envelope, error) {
	e, err := Parse(canonical)
	if err != nil {
		return Envelope{}, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return Envelope{}, fmt.Errorf("reqsig: bad public key size %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Envelope{}, fmt.Errorf("reqsig: signature not base64: %w", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return Envelope{}, fmt.Errorf("reqsig: signature verification failed")
	}
	return e, nil
}

// CheckFresh returns an error when the envelope timestamp is outside the
// [now-maxSkew, now+maxSkew] window. maxSkew <= 0 selects DefaultMaxSkew.
func CheckFresh(e Envelope, now time.Time, maxSkew time.Duration) error {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxSkew
	}
	d := now.Unix() - e.Timestamp
	if d < 0 {
		d = -d
	}
	if time.Duration(d)*time.Second > maxSkew {
		return fmt.Errorf("reqsig: envelope timestamp outside ±%s window", maxSkew)
	}
	return nil
}

// ---------------------------------------------------------------------------
// field helpers
// ---------------------------------------------------------------------------

func addrHex(network uint16, node uint32) string {
	return fmt.Sprintf("%04x%08x", network, node)
}

func parseAddrHex(s string) (uint16, uint32, error) {
	if !isLowerHex(s, 12) {
		return 0, 0, fmt.Errorf("reqsig: address must be 12 lowercase hex chars")
	}
	network, err := strconv.ParseUint(s[:4], 16, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("reqsig: address network: %w", err)
	}
	node, err := strconv.ParseUint(s[4:], 16, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("reqsig: address node: %w", err)
	}
	return uint16(network), uint32(node), nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// parseCanonicalDecimal accepts only the canonical decimal form: digits,
// no sign, no leading zeros (except "0" itself).
func parseCanonicalDecimal(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zero")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("non-digit")
		}
	}
	return strconv.ParseInt(s, 10, 64)
}

func checkAudience(s string) error {
	if len(s) == 0 || len(s) > 64 {
		return fmt.Errorf("reqsig: audience must be 1-64 chars")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return fmt.Errorf("reqsig: audience must match [a-z0-9.-]")
		}
	}
	return nil
}
