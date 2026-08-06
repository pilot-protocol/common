// SPDX-License-Identifier: AGPL-3.0-or-later

package decision

import (
	"context"
	"fmt"
	"sync"
)

// ModelUsage is provider-reported usage for one hosted semantic evaluation.
// It is attached out-of-band to the semantic response and copied into the
// durable evaluation record; it never influences authorization authority.
type ModelUsage struct {
	ModelCalls   uint64 `json:"model_calls,omitempty"`
	InputTokens  uint64 `json:"input_tokens,omitempty"`
	OutputTokens uint64 `json:"output_tokens,omitempty"`
}

func (usage ModelUsage) Validate() error {
	if usage.ModelCalls > 16 || usage.InputTokens > 100_000_000 || usage.OutputTokens > 10_000_000 {
		return fmt.Errorf("decision: invalid model usage")
	}
	if usage.ModelCalls == 0 && (usage.InputTokens != 0 || usage.OutputTokens != 0) {
		return fmt.Errorf("decision: model tokens require a model call")
	}
	return nil
}

type modelUsageContextKey struct{}

// ModelUsageRecorder is scoped to one authorization attempt. The HTTP
// semantic client reports the provider response into it, and the guarded
// authorizer snapshots it before persisting the evaluation.
type ModelUsageRecorder struct {
	mu    sync.Mutex
	usage ModelUsage
}

func WithModelUsageRecorder(ctx context.Context) (context.Context, *ModelUsageRecorder) {
	recorder := &ModelUsageRecorder{}
	return context.WithValue(ctx, modelUsageContextKey{}, recorder), recorder
}

func ReportModelUsage(ctx context.Context, usage ModelUsage) error {
	if err := usage.Validate(); err != nil {
		return err
	}
	recorder, ok := ctx.Value(modelUsageContextKey{}).(*ModelUsageRecorder)
	if !ok || recorder == nil {
		return nil
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.usage.ModelCalls != 0 {
		return fmt.Errorf("decision: model usage already reported")
	}
	recorder.usage = usage
	return nil
}

func (recorder *ModelUsageRecorder) Snapshot() ModelUsage {
	if recorder == nil {
		return ModelUsage{}
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.usage
}
