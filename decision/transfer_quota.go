// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"fmt"
	"sync"
	"time"
)

// TransferQuotaConfig bounds admitted governed transfers for each signed
// sender identity within a fixed window. It is an enforcement-plane control:
// only a transport that has already verified an Intent may consume it.
//
// A quota counts admitted attempts, including ones later rejected by a local
// content inspector or receipt recorder. This deliberately prevents a sender
// from using repeated failing deliveries to exhaust local inspection work
// without consuming its own governed-transfer budget.
type TransferQuotaConfig struct {
	Window     time.Duration
	MaxBytes   uint64
	MaxActions uint64
	MaxSenders int
	Now        func() time.Time
}

// TransferQuotaLimiter is a bounded, concurrency-safe per-sender admission
// limiter. It is local state by design. A future shared/durable limiter must
// preserve these same no-reset-on-clock-rollback semantics.
type TransferQuotaLimiter struct {
	window     time.Duration
	maxBytes   uint64
	maxActions uint64
	maxSenders int
	now        func() time.Time

	mu           sync.Mutex
	activeWindow time.Time
	used         map[string]transferQuotaUsage
}

type transferQuotaUsage struct {
	bytes   uint64
	actions uint64
}

// NewTransferQuotaLimiter validates and initializes a local quota limiter.
func NewTransferQuotaLimiter(config TransferQuotaConfig) (*TransferQuotaLimiter, error) {
	if config.Window < time.Second || config.Window > time.Hour {
		return nil, fmt.Errorf("decision: transfer quota window must be 1s-1h")
	}
	if config.MaxBytes == 0 && config.MaxActions == 0 {
		return nil, fmt.Errorf("decision: transfer quota needs a byte or action limit")
	}
	if config.MaxSenders < 1 || config.MaxSenders > 10000 {
		return nil, fmt.Errorf("decision: transfer quota max senders must be 1-10000")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &TransferQuotaLimiter{
		window: config.Window, maxBytes: config.MaxBytes, maxActions: config.MaxActions, maxSenders: config.MaxSenders,
		now: now, used: make(map[string]transferQuotaUsage),
	}, nil
}

// Allow reserves one admitted transfer for sender. An error means the caller
// must deny the delivery before any side effect. sender must be a verified
// signed agent identity, not a transport address or caller-supplied label.
func (limiter *TransferQuotaLimiter) Allow(sender string, bytes uint64) error {
	if limiter == nil {
		return nil
	}
	if sender == "" {
		return fmt.Errorf("decision: transfer quota sender is required")
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	window := limiter.now().UTC().Truncate(limiter.window)
	if limiter.activeWindow.IsZero() || window.After(limiter.activeWindow) {
		limiter.activeWindow = window
		limiter.used = make(map[string]transferQuotaUsage)
	}
	// If local clock moves backward, retain the newer active bucket instead of
	// allowing a rollback to reset an already consumed quota.
	usage, exists := limiter.used[sender]
	if !exists && len(limiter.used) >= limiter.maxSenders {
		return fmt.Errorf("decision: transfer quota sender capacity exceeded")
	}
	if limiter.maxActions != 0 && usage.actions >= limiter.maxActions {
		return fmt.Errorf("decision: transfer quota action limit exceeded")
	}
	if limiter.maxBytes != 0 && (bytes > limiter.maxBytes || usage.bytes > limiter.maxBytes-bytes) {
		return fmt.Errorf("decision: transfer quota byte limit exceeded")
	}
	usage.actions++
	usage.bytes += bytes
	limiter.used[sender] = usage
	return nil
}
