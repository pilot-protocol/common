// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"sync"
	"testing"
)

// fakeBus implements EventBus for the panic-survival test. Records
// every published topic so the test can assert the boundary emitted
// the expected event.
type fakeBus struct {
	mu     sync.Mutex
	topics []string
}

func (b *fakeBus) Publish(topic string, _ map[string]any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.topics = append(b.topics, topic)
}

func (b *fakeBus) Subscribe(_ string) (<-chan Event, func()) {
	ch := make(chan Event)
	return ch, func() {}
}

func (b *fakeBus) latest() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.topics))
	copy(out, b.topics)
	return out
}

// TestL11PluginPanicSurvival exercises the L11 boundary
// (RecoverPlugin) by inducing a panic in a goroutine guarded by it.
// Verifies:
//  1. process survives
//  2. PluginRecoveredPanicCount increments
//  3. a "plugin.<name>.panic" event lands on the bus
//  4. the onPanic callback fires with the panic value
func TestL11PluginPanicSurvival(t *testing.T) {
	t.Parallel()
	before := PluginRecoveredPanicCount()
	bus := &fakeBus{}

	var (
		gotPanicValue any
		callbackCount int
		mu            sync.Mutex
	)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer RecoverPlugin("testplugin", "acceptLoop", bus, func(r any) {
			mu.Lock()
			defer mu.Unlock()
			gotPanicValue = r
			callbackCount++
		})
		panic("L11 boundary test panic")
	}()
	wg.Wait()

	if PluginRecoveredPanicCount() <= before {
		t.Fatal("L11 boundary did not record the panic")
	}

	mu.Lock()
	defer mu.Unlock()
	if callbackCount != 1 {
		t.Fatalf("onPanic callback fired %d times, want 1", callbackCount)
	}
	if s, ok := gotPanicValue.(string); !ok || s != "L11 boundary test panic" {
		t.Fatalf("onPanic got %v (%T), want string 'L11 boundary test panic'", gotPanicValue, gotPanicValue)
	}

	// Bus event should be "plugin.testplugin.panic".
	found := false
	for _, topic := range bus.latest() {
		if topic == "plugin.testplugin.panic" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("plugin.testplugin.panic event not on bus: got %v", bus.latest())
	}
}

// TestL11PluginPanicNilBus confirms the boundary is nil-safe when no
// bus is provided (e.g., the standalone nameserver binary).
func TestL11PluginPanicNilBus(t *testing.T) {
	t.Parallel()
	before := PluginRecoveredPanicCount()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer RecoverPlugin("nullbus", "op", nil, nil)
		panic("nil-bus panic")
	}()
	wg.Wait()
	if PluginRecoveredPanicCount() <= before {
		t.Fatal("L11 boundary did not record nil-bus panic")
	}
}

// TestL11PluginPanicCallbackPanicSwallowed checks the defensive guard
// against a panicking onPanic callback.
func TestL11PluginPanicCallbackPanicSwallowed(t *testing.T) {
	t.Parallel()
	before := PluginRecoveredPanicCount()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer RecoverPlugin("buggy", "op", nil, func(_ any) {
			panic("callback-itself-panics")
		})
		panic("primary panic")
	}()
	wg.Wait()
	if PluginRecoveredPanicCount() <= before {
		t.Fatal("L11 boundary did not record the primary panic")
	}
}

// TestL11PerPluginUnhealthy verifies per-plugin panic tracking
// and the unhealthy-signal fires once when the threshold is crossed.
func TestL11PerPluginUnhealthy(t *testing.T) {
	ResetPluginHealthForTest()
	bus := &fakeBus{}
	const name = "unstable-plugin"

	if !IsPluginHealthy(name) || PluginPanicCount(name) != 0 {
		t.Fatal("fresh plugin unhealthy or non-zero count")
	}

	// Induce panics up to threshold-1; plugin stays healthy.
	boom := func() {
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() { defer wg.Done(); defer RecoverPlugin(name, "loop", bus, nil); panic("x") }()
		wg.Wait()
	}
	for i := 1; i < maxPanicsBeforeUnhealthy; i++ {
		boom()
		if got := PluginPanicCount(name); got != uint64(i) || !IsPluginHealthy(name) {
			t.Fatalf("panic %d: count=%d healthy=%v", i, got, IsPluginHealthy(name))
		}
	}

	// Threshold-crossing panic makes plugin unhealthy + fires event.
	boom()
	if IsPluginHealthy(name) {
		t.Fatal("plugin should be unhealthy after threshold")
	}
	found := false
	for _, tp := range bus.topics {
		if tp == "plugin."+name+".unhealthy" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unhealthy event missing, topics: %v", bus.topics)
	}

	// One-shot: extra panic does not re-fire unhealthy.
	before := 0
	for _, tp := range bus.topics {
		if tp == "plugin."+name+".unhealthy" {
			before++
		}
	}
	boom()
	after := 0
	for _, tp := range bus.topics {
		if tp == "plugin."+name+".unhealthy" {
			after++
		}
	}
	if after != before {
		t.Fatalf("unhealthy event re-fired (%d→%d)", before, after)
	}
	ResetPluginHealthForTest()
}
