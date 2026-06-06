// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi_test

import (
	"context"
	"errors"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
)

func TestServiceRegistry_StartAllTwiceReturnsErrRegistryStarted(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	_ = sr.Register(&fakeService{name: "a", order: 1})
	if err := sr.StartAll(context.Background(), coreapi.Deps{}); err != nil {
		t.Fatalf("first StartAll: %v", err)
	}
	err := sr.StartAll(context.Background(), coreapi.Deps{})
	if !errors.Is(err, coreapi.ErrRegistryStarted) {
		t.Errorf("second StartAll = %v, want ErrRegistryStarted", err)
	}
}

func TestServiceRegistry_StopAllSurfacesFirstError(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	a := &fakeService{name: "a", order: 1, stopErr: errors.New("stop-a-failed")}
	b := &fakeService{name: "b", order: 2, stopErr: errors.New("stop-b-failed")}
	_ = sr.Register(a)
	_ = sr.Register(b)
	if err := sr.StartAll(context.Background(), coreapi.Deps{}); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	// b stops first (reverse order), so its error is "first" returned.
	err := sr.StopAll(context.Background())
	if err == nil || err.Error() != "stop-b-failed" {
		t.Errorf("StopAll = %v, want stop-b-failed", err)
	}
}

func TestServiceRegistry_StopAllStopsAllEvenAfterError(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	aStopped := false
	bStopped := false
	a := &recordingStopWithErr{name: "a", order: 1, stopped: &aStopped}
	b := &recordingStopWithErr{name: "b", order: 2, stopped: &bStopped, err: errors.New("b-failed")}
	_ = sr.Register(a)
	_ = sr.Register(b)
	_ = sr.StartAll(context.Background(), coreapi.Deps{})
	_ = sr.StopAll(context.Background())
	if !aStopped {
		t.Error("service a was not stopped despite b's error")
	}
	if !bStopped {
		t.Error("service b was not stopped")
	}
}

func TestServiceRegistry_StopAllTimingOutHangingPlugin(t *testing.T) {
	t.Parallel()
	sr := &coreapi.ServiceRegistry{}
	bStopped := false
	a := &hangingService{name: "a", order: 1}
	bb := &recordingStopWithErr{name: "b", order: 2, stopped: &bStopped}
	_ = sr.Register(a)
	_ = sr.Register(bb)
	_ = sr.StartAll(context.Background(), coreapi.Deps{})
	// StopAll should not block forever; the hanging plugin should time out
	err := sr.StopAll(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("StopAll = %v, want DeadlineExceeded from hung plugin a", err)
	}
	if !bStopped {
		t.Error("service b was not stopped despite a hanging")
	}
}

// hangingService never returns from Stop — simulates a plugin that
// blocks indefinitely, used to verify per-plugin timeout in StopAll.
type hangingService struct {
	name  string
	order int
}

func (h *hangingService) Name() string                                       { return h.name }
func (h *hangingService) Order() int                                         { return h.order }
func (h *hangingService) Start(ctx context.Context, deps coreapi.Deps) error { return nil }
func (h *hangingService) Stop(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

type recordingStopWithErr struct {
	name    string
	order   int
	stopped *bool
	err     error
}

func (r *recordingStopWithErr) Name() string                                       { return r.name }
func (r *recordingStopWithErr) Order() int                                         { return r.order }
func (r *recordingStopWithErr) Start(ctx context.Context, deps coreapi.Deps) error { return nil }
func (r *recordingStopWithErr) Stop(ctx context.Context) error {
	*r.stopped = true
	return r.err
}
