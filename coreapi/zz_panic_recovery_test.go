// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi_test

// Regression for P1 plugin-crash DoS: StartAll invokes each plugin's
// Start() directly with no recover wrapper. A plugin that panics
// during Start (nil-deref, index OOB, etc.) crashes the entire daemon
// process — operator's recourse is to find the buggy plugin via
// stack trace and disable it, while every other plugin is offline.
//
// Fix: StartAll wraps each plugin Start() in defer recover(), converts
// the panic to an error like any other Start failure. The error path
// (return on first failure, previously-started plugins NOT auto-
// stopped) is preserved — the caller's Stop() handles cleanup.

import (
	"context"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
)

// panickingService panics during Start with the given message.
type panickingService struct{ msg string }

func (p *panickingService) Name() string                                  { return "panicker" }
func (p *panickingService) Order() int                                    { return 100 }
func (p *panickingService) Start(_ context.Context, _ coreapi.Deps) error { panic(p.msg) }
func (p *panickingService) Stop(_ context.Context) error                  { return nil }

// panickingStop panics during Stop with the given message.
type panickingStop struct{ msg string }

func (p *panickingStop) Name() string                                  { return "panicker-stop" }
func (p *panickingStop) Order() int                                    { return 100 }
func (p *panickingStop) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (p *panickingStop) Stop(_ context.Context) error                  { panic(p.msg) }

func TestServiceRegistry_StopAllRecoversFromPluginPanic(t *testing.T) {
	t.Parallel()

	sr := &coreapi.ServiceRegistry{}
	if err := sr.Register(&panickingStop{msg: "boom during shutdown"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Start first so the service is in the started queue.
	if err := sr.StartAll(context.Background(), coreapi.Deps{}); err != nil {
		t.Fatalf("StartAll: %v", err)
	}

	// Without the recover wrapper in StopAll, this CRASHES the test process.
	err := sr.StopAll(context.Background())

	if err == nil {
		t.Fatal("StopAll returned nil for panicking plugin — recover wrapper missing")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("expected error to mention 'panic'; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "boom during shutdown") {
		t.Errorf("expected error to include the panic message; got %q", err.Error())
	}
}

// stopThenPanic panics during Stop AFTER calling an observer so the
// test can verify downstream services still get their Stop calls.
type stopThenPanic struct {
	name   string
	order  int
	called *bool
	msg    string
}

func (s *stopThenPanic) Name() string                                  { return s.name }
func (s *stopThenPanic) Order() int                                    { return s.order }
func (s *stopThenPanic) Start(_ context.Context, _ coreapi.Deps) error { return nil }
func (s *stopThenPanic) Stop(_ context.Context) error {
	*s.called = true
	panic(s.msg)
}

func TestServiceRegistry_StopAllContinuesAfterPanic(t *testing.T) {
	t.Parallel()

	sr := &coreapi.ServiceRegistry{}

	laterCalled := false
	panicker := &stopThenPanic{name: "panicker", order: 50, called: new(bool), msg: "crash"}
	later := &stopThenPanic{name: "later", order: 100, called: &laterCalled, msg: ""}

	// later.Order > panicker.Order → later stops first (reverse order).
	// panicker panics in Stop; later should already have been stopped.
	for _, s := range []coreapi.Service{panicker, later} {
		if err := sr.Register(s); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}

	if err := sr.StartAll(context.Background(), coreapi.Deps{}); err != nil {
		t.Fatalf("StartAll: %v", err)
	}

	_ = sr.StopAll(context.Background())

	// later must have been stopped despite panicker panicking earlier
	// (later starts first, so it stops first — reverse order).
	if !laterCalled {
		t.Error("downstream service was not stopped after panicker; StopAll aborted early")
	}
}

func TestServiceRegistry_StartAllRecoversFromPluginPanic(t *testing.T) {
	t.Parallel()

	sr := &coreapi.ServiceRegistry{}
	if err := sr.Register(&panickingService{msg: "boom from a buggy plugin"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Without the recover wrapper, this CRASHES the test process.
	err := sr.StartAll(context.Background(), coreapi.Deps{})

	if err == nil {
		t.Fatal("StartAll returned nil for panicking plugin — recover wrapper missing")
	}
	if !strings.Contains(err.Error(), "panic") {
		t.Errorf("expected error to mention 'panic'; got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "boom from a buggy plugin") {
		t.Errorf("expected error to include the panic message; got %q", err.Error())
	}
}
