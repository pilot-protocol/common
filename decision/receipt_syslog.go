// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"fmt"
	"strings"
	"time"
)

// ReceiptRFC5424 formats signed enforcement evidence as an RFC 5424 syslog
// event. It deliberately carries receipt metadata and signature only; raw
// application payloads are represented by the receipt's signed hashes.
func ReceiptRFC5424(receipt Receipt) (string, error) {
	if err := receipt.Validate(); err != nil {
		return "", err
	}
	fields := []struct{ key, value string }{
		{"receipt_id", receipt.ID}, {"tenant_id", receipt.TenantID}, {"agent_id", receipt.AgentID},
		{"decision_id", receipt.DecisionID}, {"decision_hash", receipt.DecisionHash}, {"intent_hash", receipt.IntentHash},
		{"mandate_id", receipt.MandateID}, {"outcome", string(receipt.Outcome)}, {"result", string(receipt.Result)},
		{"enforcement_point", receipt.EnforcementPoint}, {"key_id", receipt.KeyID}, {"signature", receipt.Signature},
	}
	structured := make([]string, 0, len(fields))
	for _, field := range fields {
		if field.value != "" {
			structured = append(structured, field.key+`="`+rfc5424Escape(field.value)+`"`)
		}
	}
	// local0.info, RFC 5424 version 1. Timestamp reflects the signed
	// observation time rather than collector arrival time.
	return fmt.Sprintf("<134>1 %s - pilot - PILOT_RECEIPT [pilot@32473 %s] signed enforcement receipt", time.Unix(receipt.ObservedAt, 0).UTC().Format(time.RFC3339), strings.Join(structured, " ")), nil
}

func rfc5424Escape(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(value)
}
