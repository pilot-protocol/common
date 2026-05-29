// SPDX-License-Identifier: AGPL-3.0-or-later

package coreapi

import (
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// pluginRecoveredPanicCount is the L11 counterpart to the daemon's
// internal recoveredPanicCount. Tracks how many panics have been
// caught at plugin entry points (acceptLoop, handleConn, Service.Start
// goroutines). Exposed via PluginRecoveredPanicCount.
var pluginRecoveredPanicCount atomic.Uint64

// PluginRecoveredPanicCount returns the total number of panics
// swallowed by RecoverPlugin since process start.
func PluginRecoveredPanicCount() uint64 {
	return pluginRecoveredPanicCount.Load()
}

// ResetPluginRecoveredPanicCountForTest is test-only.
func ResetPluginRecoveredPanicCountForTest() {
	pluginRecoveredPanicCount.Store(0)
}

// maxPanicsBeforeUnhealthy is the per-plugin panic threshold.
// After this many panics, IsPluginHealthy returns false and a
// "plugin.<name>.unhealthy" event is published (once).
const maxPanicsBeforeUnhealthy = 3

// pluginPanicCounts maps plugin name → per-plugin panic counter.
// Used by IsPluginHealthy and RecoverPlugin to detect plugins that
// have exceeded the max-panics threshold and should be restarted
// or unloaded by the daemon supervisor.
var pluginPanicCounts sync.Map // map[string]*atomic.Uint64

// PluginPanicCount returns how many panics RecoverPlugin has caught
// for the named plugin since process start (or last reset).
func PluginPanicCount(name string) uint64 {
	if v, ok := pluginPanicCounts.Load(name); ok {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

// IsPluginHealthy returns false when a plugin has exceeded
// maxPanicsBeforeUnhealthy panics caught by RecoverPlugin.
func IsPluginHealthy(name string) bool {
	return PluginPanicCount(name) < maxPanicsBeforeUnhealthy
}

// ResetPluginHealthForTest clears all per-plugin panic counters.
func ResetPluginHealthForTest() {
	pluginPanicCounts.Range(func(key, _ any) bool {
		pluginPanicCounts.Delete(key)
		return true
	})
	ResetPluginRecoveredPanicCountForTest()
}

// RecoverPlugin is the L11 panic-recovery shim used at the top of
// every plugin entrypoint goroutine: Service.Start helper goroutines,
// acceptLoop, and per-connection handlers. Usage:
//
//	defer coreapi.RecoverPlugin("eventstream", "acceptLoop", events, nil)
//
// On panic it:
//  1. Recovers (caller goroutine continues / loop iteration is dropped)
//  2. Logs at ERROR with structured plugin/op fields, panic value, and
//     full goroutine stack trace
//  3. Increments PluginRecoveredPanicCount and per-plugin panic count
//  4. Publishes a "plugin.<plugin>.panic" event on the bus (if
//     events != nil) so observability subscribers see the recovery
//  5. When the per-plugin panic count reaches maxPanicsBeforeUnhealthy
//     (3), publishes one "plugin.<plugin>.unhealthy" event — the daemon
//     supervisor should react by restarting or unloading the plugin
//  6. Calls onPanic(r) if non-nil — typical use is per-conn close,
//     or signaling a future per-plugin supervisor for restart
//
// This must be the OUTERMOST defer in the goroutine: defers run LIFO,
// so other defers (conn.Close, mu.Unlock, removeSub) run first.
func RecoverPlugin(plugin, op string, events EventBus, onPanic func(any)) {
	r := recover()
	if r == nil {
		return
	}

	// Global counter.
	globalCount := pluginRecoveredPanicCount.Add(1)

	// Per-plugin counter (lazily allocate).
	perPluginVal, _ := pluginPanicCounts.LoadOrStore(plugin, new(atomic.Uint64))
	perPlugin := perPluginVal.(*atomic.Uint64)
	perPluginCount := perPlugin.Add(1)

	slog.Error("plugin panic recovered",
		"layer", "L11",
		"plugin", plugin,
		"op", op,
		"panic", r,
		"recovered_total", globalCount,
		"plugin_panics", perPluginCount,
		"stack", string(debug.Stack()),
	)

	if events != nil {
		// Defensive: a publisher that itself panics must not propagate.
		func() {
			defer func() { _ = recover() }()
			events.Publish("plugin."+plugin+".panic", map[string]any{
				"plugin":           plugin,
				"op":               op,
				"panic":            fmt.Sprintf("%v", r),
				"recovered_total":  globalCount,
				"plugin_panics":    perPluginCount,
			})
		}()

		// One-shot unhealthy event when the threshold is crossed.
		if perPluginCount == maxPanicsBeforeUnhealthy {
			func() {
				defer func() { _ = recover() }()
				events.Publish("plugin."+plugin+".unhealthy", map[string]any{
					"plugin":          plugin,
					"plugin_panics":   perPluginCount,
					"recovered_total": globalCount,
				})
			}()
		}
	}

	if onPanic != nil {
		func() {
			defer func() { _ = recover() }()
			onPanic(r)
		}()
	}
}
