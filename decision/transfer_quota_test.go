// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"strings"
	"testing"
	"time"
)

func TestTransferQuotaLimiterBoundsVerifiedSendersAndResetsOnlyForward(t *testing.T) {
	now := time.Date(2026, 8, 1, 12, 0, 10, 0, time.UTC)
	limiter, err := NewTransferQuotaLimiter(TransferQuotaConfig{
		Window: time.Minute, MaxBytes: 10, MaxActions: 2, MaxSenders: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow("sender-a", 6); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow("sender-a", 5); err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("byte limit error=%v", err)
	}
	if err := limiter.Allow("sender-a", 4); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow("sender-a", 0); err == nil || !strings.Contains(err.Error(), "action limit") {
		t.Fatalf("action limit error=%v", err)
	}
	if err := limiter.Allow("sender-b", 1); err != nil {
		t.Fatal(err)
	}
	if err := limiter.Allow("sender-c", 1); err == nil || !strings.Contains(err.Error(), "sender capacity") {
		t.Fatalf("sender capacity error=%v", err)
	}

	now = now.Add(-time.Minute)
	if err := limiter.Allow("sender-a", 1); err == nil || !strings.Contains(err.Error(), "action limit") {
		t.Fatalf("clock rollback reset quota: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := limiter.Allow("sender-c", 10); err != nil {
		t.Fatalf("forward window did not reset quota: %v", err)
	}
}

func TestTransferQuotaLimiterValidatesConfiguration(t *testing.T) {
	for _, config := range []TransferQuotaConfig{
		{},
		{Window: time.Second, MaxSenders: 1},
		{Window: 500 * time.Millisecond, MaxBytes: 1, MaxSenders: 1},
		{Window: time.Second, MaxBytes: 1, MaxSenders: 10001},
	} {
		if _, err := NewTransferQuotaLimiter(config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}
