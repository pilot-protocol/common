// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestPresidioExternalIntegration(t *testing.T) {
	endpoint := os.Getenv("PILOT_TEST_PRESIDIO_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PILOT_TEST_PRESIDIO_ENDPOINT to run against a local Presidio Analyzer")
	}
	inspector := PresidioInspector{Endpoint: endpoint, Entities: []string{"EMAIL_ADDRESS"}}
	if err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "text/plain", "", strings.NewReader("the blue bicycle is parked")); err != nil {
		t.Fatalf("clean content rejected: %v", err)
	}
	if err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "text/plain", "", strings.NewReader("contact pilot@example.com")); err == nil || err.Error() != "presidio: sensitive content detected" {
		t.Fatalf("email content inspection error=%v", err)
	}
}
