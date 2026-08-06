// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const FederatedContentVersion uint16 = 1

// FederatedContent is the exact exchange body submitted to Pilot's hosted
// federation boundary. Disclosure is signed into the Intent through
// Intent.PayloadHash; it in turn binds the body hash, byte length, media type,
// recipient, purpose, residency, filename, labels, and retention class.
//
// Body is deliberately absent from Decisions, approval transactions,
// evaluation journals, and action receipts. The hosted exchange repository
// encrypts it separately for the tenant-scoped operator experience.
type FederatedContent struct {
	Version    uint16            `json:"version"`
	Disclosure DisclosureBinding `json:"disclosure"`
	Body       []byte            `json:"body"`
}

func NewFederatedContent(disclosure DisclosureBinding, body []byte) (FederatedContent, error) {
	content := FederatedContent{
		Version: FederatedContentVersion,
		Disclosure: DisclosureBinding{
			Version: disclosure.Version, ContentHash: disclosure.ContentHash,
			DeclaredBytes: disclosure.DeclaredBytes, ContentType: disclosure.ContentType,
			Labels: append([]string(nil), disclosure.Labels...), Recipient: disclosure.Recipient,
			Purpose: disclosure.Purpose, Residency: disclosure.Residency, Filename: disclosure.Filename,
			TransferID: disclosure.TransferID, RetentionClass: disclosure.RetentionClass,
		},
		Body: append([]byte(nil), body...),
	}
	if err := content.Validate(); err != nil {
		return FederatedContent{}, err
	}
	return content, nil
}

func (content FederatedContent) Validate() error {
	if content.Version != FederatedContentVersion {
		return fmt.Errorf("decision: unsupported federated content version %d", content.Version)
	}
	if err := content.Disclosure.Validate(); err != nil {
		return err
	}
	if uint64(len(content.Body)) != content.Disclosure.DeclaredBytes {
		return fmt.Errorf("decision: federated content byte length does not match disclosure")
	}
	sum := sha256.Sum256(content.Body)
	if hex.EncodeToString(sum[:]) != content.Disclosure.ContentHash {
		return fmt.Errorf("decision: federated content hash does not match disclosure")
	}
	return nil
}

func (content FederatedContent) VerifyIntent(intent Intent) error {
	if err := content.Validate(); err != nil {
		return err
	}
	return content.Disclosure.VerifyIntent(intent)
}

func (content FederatedContent) Clone() FederatedContent {
	cloned, _ := NewFederatedContent(content.Disclosure, content.Body)
	return cloned
}
