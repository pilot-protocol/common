// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"strings"
	"testing"
)

func TestReceiptRFC5424CarriesSignedEvidenceWithoutPayload(t *testing.T) {
	receipt := journalReceipt(t, 1785500000, Enforced)
	line, err := ReceiptRFC5424(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"<134>1 2026-07-31T", "PILOT_RECEIPT", `receipt_id="` + receipt.ID + `"`,
		`tenant_id="` + receipt.TenantID + `"`, `decision_hash="` + receipt.DecisionHash + `"`,
		`signature="` + receipt.Signature + `"`, "signed enforcement receipt",
	} {
		if !strings.Contains(line, expected) {
			t.Fatalf("RFC5424 receipt missing %q: %s", expected, line)
		}
	}
	if strings.Contains(line, "payload") {
		t.Fatalf("RFC5424 receipt unexpectedly contains payload field: %s", line)
	}
}

func TestRFC5424Escape(t *testing.T) {
	if got, want := rfc5424Escape(`a\\b"c]`), `a\\\\b\"c\]`; got != want {
		t.Fatalf("escape=%q want=%q", got, want)
	}
}
