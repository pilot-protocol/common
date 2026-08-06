// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// DisclosureBindingVersion preserves the original V1 canonical bytes.
	// Callers that do not need retention metadata should continue to use it.
	DisclosureBindingVersion uint16 = 1
	// DisclosureBindingRetentionVersion adds a policy-selected retention class
	// without changing V1 Intent or disclosure hashes.
	DisclosureBindingRetentionVersion uint16 = 2
	DisclosureBindingDomain                  = "pilot-disclosure-binding-v1"
	DisclosureBindingRetentionDomain         = "pilot-disclosure-binding-v2"
)

// DisclosureBinding is canonical privacy metadata for a governed disclosure.
// It deliberately carries hashes and declared characteristics, never the
// application body. V1 Intents bind it by placing Hash() in PayloadHash; this
// leaves historical Intent and Receipt canonicalization unchanged.
type DisclosureBinding struct {
	Version       uint16   `json:"version"`
	ContentHash   string   `json:"content_hash"`
	DeclaredBytes uint64   `json:"declared_bytes"`
	ContentType   string   `json:"content_type"`
	Labels        []string `json:"labels"`
	Recipient     string   `json:"recipient"`
	Purpose       string   `json:"purpose"`
	Residency     string   `json:"residency"`
	Filename      string   `json:"filename,omitempty"`
	TransferID    string   `json:"transfer_id,omitempty"`
	// RetentionClass is available only in V2. It is an opaque, tenant-defined
	// class (for example "finance-7y"), not an unsupported claim that the
	// receiver has already performed deletion or legal-hold operations.
	RetentionClass string `json:"retention_class,omitempty"`
}

func (binding DisclosureBinding) Validate() error {
	switch binding.Version {
	case DisclosureBindingVersion:
		if binding.RetentionClass != "" {
			return fmt.Errorf("decision: disclosure retention_class requires version %d", DisclosureBindingRetentionVersion)
		}
	case DisclosureBindingRetentionVersion:
		if !validDisclosureLabel(binding.RetentionClass) {
			return fmt.Errorf("decision: invalid disclosure retention_class %q", binding.RetentionClass)
		}
	default:
		return fmt.Errorf("decision: disclosure binding version %d is unsupported", binding.Version)
	}
	if !lowerHex(binding.ContentHash, 64) {
		return fmt.Errorf("decision: disclosure content_hash must be 64 lowercase hex characters")
	}
	if err := validateDisclosureContentType(binding.ContentType); err != nil {
		return err
	}
	if len(binding.Labels) == 0 || len(binding.Labels) > 16 {
		return fmt.Errorf("decision: disclosure requires 1-16 labels")
	}
	for index, label := range binding.Labels {
		if !validDisclosureLabel(label) {
			return fmt.Errorf("decision: invalid disclosure label %q", label)
		}
		if index > 0 && binding.Labels[index-1] >= label {
			return fmt.Errorf("decision: disclosure labels must be strictly sorted")
		}
	}
	if err := validateText("disclosure recipient", binding.Recipient, 256, false); err != nil {
		return err
	}
	if err := validateText("disclosure purpose", binding.Purpose, 256, false); err != nil {
		return err
	}
	if !validDisclosureResidency(binding.Residency) {
		return fmt.Errorf("decision: invalid disclosure residency %q", binding.Residency)
	}
	if binding.Filename != "" && (!utf8.ValidString(binding.Filename) || len(binding.Filename) > 256 || filepath.Base(binding.Filename) != binding.Filename || strings.ContainsAny(binding.Filename, "/\\")) {
		return fmt.Errorf("decision: invalid disclosure filename")
	}
	if binding.TransferID != "" {
		if err := validateText("disclosure transfer_id", binding.TransferID, 256, false); err != nil {
			return err
		}
	}
	return nil
}

func (binding DisclosureBinding) Canonical() ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	writer := canonicalWriter{}
	if binding.Version == DisclosureBindingVersion {
		writer.string(DisclosureBindingDomain)
	} else {
		writer.string(DisclosureBindingRetentionDomain)
	}
	writer.u16(binding.Version)
	writer.string(binding.ContentHash)
	writer.u64(binding.DeclaredBytes)
	writer.string(binding.ContentType)
	writer.u16(uint16(len(binding.Labels)))
	for _, label := range binding.Labels {
		writer.string(label)
	}
	writer.string(binding.Recipient)
	writer.string(binding.Purpose)
	writer.string(binding.Residency)
	writer.string(binding.Filename)
	writer.string(binding.TransferID)
	if binding.Version == DisclosureBindingRetentionVersion {
		writer.string(binding.RetentionClass)
	}
	return writer.Bytes(), nil
}

func (binding DisclosureBinding) Hash() (string, error) { return hashCanonical(binding.Canonical()) }

// VerifyIntent proves that the caller signed this exact disclosure binding
// into a legacy V1 Intent without changing that Intent's canonical bytes.
func (binding DisclosureBinding) VerifyIntent(intent Intent) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	hash, err := binding.Hash()
	if err != nil {
		return err
	}
	if intent.PayloadHash != hash {
		return fmt.Errorf("decision: intent does not bind this disclosure")
	}
	if intent.Audience != binding.Recipient || intent.Purpose != binding.Purpose {
		return fmt.Errorf("decision: intent disclosure audience or purpose mismatch")
	}
	return nil
}

func validateDisclosureContentType(value string) error {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) {
		return fmt.Errorf("decision: invalid disclosure content_type")
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || len(parameters) != 0 || mediaType != value || !strings.Contains(mediaType, "/") {
		return fmt.Errorf("decision: invalid disclosure content_type")
	}
	return nil
}

func validDisclosureLabel(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' && index > 0 && index+1 < len(value)) {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}

func validDisclosureResidency(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}
