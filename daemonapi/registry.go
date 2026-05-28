// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// The plugin pluginReg is a process-global, append-only map. Plugin
// packages call RegisterPlugin from their own init() block; the
// daemon engine later calls LoadAll to bring every registered plugin
// online against a specific Daemon.
//
// This decouples the daemon from compile-time knowledge of which
// plugins exist: cmd/daemon/main.go blank-imports the desired
// plugins, each plugin's init() registers itself, and the daemon
// iterates pluginReg contents at startup. Adding or removing a
// plugin from a binary is one blank-import line; no daemon or
// plugin code changes.
//
// The same mechanism works for in-process plugins (Go packages
// linked into the binary) and for runtime plugins (Go plugin.Open
// of .so files). The .so's init() block calls RegisterPlugin the
// same way, and LoadAll picks it up identically.

var (
	pluginRegMu sync.Mutex
	pluginReg   = make(map[string]Factory)
)

// RegisterPlugin records a factory under name. Typical use:
//
//	func init() {
//	    daemonapi.RegisterPlugin("handshake", func() daemonapi.Plugin {
//	        return &handshakePlugin{}
//	    })
//	}
//
// Registering twice with the same name is a programming error and
// panics — two factories under one name would race in LoadAll. The
// panic surfaces during package init, not at runtime, which makes
// the conflict obvious in test output and at first daemon launch.
func RegisterPlugin(name string, f Factory) {
	if name == "" {
		panic("daemonapi: RegisterPlugin: empty name")
	}
	if f == nil {
		panic("daemonapi: RegisterPlugin: nil factory for " + name)
	}
	pluginRegMu.Lock()
	defer pluginRegMu.Unlock()
	if _, exists := pluginReg[name]; exists {
		panic("daemonapi: plugin already registered: " + name)
	}
	pluginReg[name] = f
}

// Registered returns the names of every registered plugin, sorted.
// Useful for status output and for tests that want to verify a
// blank-import set wired the expected plugins in.
func Registered() []string {
	pluginRegMu.Lock()
	defer pluginRegMu.Unlock()
	names := make([]string, 0, len(pluginReg))
	for n := range pluginReg {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// LoadAll instantiates every registered plugin against d and calls
// Init in sorted-by-name order. Returns the slice of loaded plugins
// so the caller can drive Shutdown later, plus the first error
// encountered (subsequent plugins are not started after a failure).
//
// Plugins are returned in registration-sorted order so Shutdown can
// run them in reverse and respect inter-plugin ordering by giving
// later-named plugins priority during teardown. This matches the
// common pattern where alphabetic name choice doubles as a startup-
// order hint (a-something starts before z-something).
func LoadAll(d Daemon) ([]Plugin, error) {
	pluginRegMu.Lock()
	names := make([]string, 0, len(pluginReg))
	for n := range pluginReg {
		names = append(names, n)
	}
	sort.Strings(names)
	factories := make([]Factory, len(names))
	for i, n := range names {
		factories[i] = pluginReg[n]
	}
	pluginRegMu.Unlock()

	loaded := make([]Plugin, 0, len(names))
	for i, name := range names {
		p := factories[i]()
		if p == nil {
			return loaded, fmt.Errorf("daemonapi: plugin %q factory returned nil", name)
		}
		if err := p.Init(d); err != nil {
			return loaded, fmt.Errorf("daemonapi: plugin %q init: %w", name, err)
		}
		loaded = append(loaded, p)
	}
	return loaded, nil
}

// ShutdownAll calls Shutdown on every plugin in REVERSE-sorted order
// (the inverse of LoadAll's startup order). Each Shutdown gets the
// same context — typically a deadline-bound context from the daemon's
// shutdown timeout. Errors are collected and returned as a wrapped
// multi-error so the daemon still attempts to shut down every plugin
// even if an earlier one returned an error.
func ShutdownAll(ctx context.Context, plugins []Plugin) error {
	var errs []error
	for i := len(plugins) - 1; i >= 0; i-- {
		if err := plugins[i].Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("plugin %q shutdown: %w", plugins[i].Name(), err))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	// Join the errors; the daemon's caller can errors.Is / errors.As
	// to inspect individual plugin failures.
	msg := errs[0].Error()
	for _, e := range errs[1:] {
		msg += "; " + e.Error()
	}
	return fmt.Errorf("daemonapi: %d plugin shutdown error(s): %s", len(errs), msg)
}

// resetRegistry clears the pluginReg. Tests only — no production code
// needs this. Kept package-private; callers that genuinely need to
// reset state in tests can declare their own helper using a build
// tag and a copy of this function.
func resetRegistry() {
	pluginRegMu.Lock()
	defer pluginRegMu.Unlock()
	pluginReg = make(map[string]Factory)
}
