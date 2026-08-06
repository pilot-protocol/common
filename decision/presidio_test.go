// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPresidioInspectorRejectsDetectedContentWithoutLeakingIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/analyze" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		var body presidioAnalysisRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Text != "ssn 123-45-6789" || body.Language != "en" || len(body.Entities) != 1 || body.Entities[0] != "US_SSN" {
			t.Fatalf("request body = %+v", body)
		}
		_, _ = io.WriteString(response, `[{"entity_type":"US_SSN","score":0.9}]`)
	}))
	defer server.Close()

	err := (PresidioInspector{Endpoint: server.URL, Entities: []string{"US_SSN"}}).InspectDisclosureContent(context.Background(), Intent{}, nil, "text/plain; charset=utf-8", "", strings.NewReader("ssn 123-45-6789"))
	if err == nil || err.Error() != "presidio: sensitive content detected" || strings.Contains(err.Error(), "123-45-6789") {
		t.Fatalf("inspection error = %v", err)
	}
}

func TestPresidioInspectorAllowsCleanContentAndFailsClosed(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		switch calls {
		case 1:
			_, _ = io.WriteString(response, `[]`)
		default:
			http.Error(response, "unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	inspector := PresidioInspector{Endpoint: server.URL, ScoreThreshold: 0.8}
	if err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "application/json", "", strings.NewReader(`{"safe":true}`)); err != nil {
		t.Fatalf("clean inspection error = %v", err)
	}
	if err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "application/json", "", strings.NewReader(`{"safe":true}`)); err == nil || !strings.Contains(err.Error(), "analyzer returned status 503") {
		t.Fatalf("unavailable inspection error = %v", err)
	}
	if err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "application/pdf", "", strings.NewReader("not sent")); err == nil || !strings.Contains(err.Error(), "cannot be inspected") {
		t.Fatalf("binary inspection error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("unexpected analyzer calls = %d", calls)
	}
}

func TestPresidioInspectorBoundsContentBeforeSendingIt(t *testing.T) {
	inspector := PresidioInspector{Endpoint: "http://127.0.0.1:1", MaxBytes: 4}
	err := inspector.InspectDisclosureContent(context.Background(), Intent{}, nil, "text/plain", "", strings.NewReader("12345"))
	if err == nil || !strings.Contains(err.Error(), "exceeds local inspection limit") {
		t.Fatalf("oversize inspection error = %v", err)
	}
}
