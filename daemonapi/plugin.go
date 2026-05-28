// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import "context"

// Plugin is the lifecycle contract every daemon plugin implements.
// The daemon calls Init once after the engine is running and Shutdown
// once when the engine is stopping. Name returns a stable identifier
// used for registration, log lines, and metrics labels.
//
// A plugin holds the Daemon it was initialized with for the rest of
// its lifetime; the daemon engine will not be replaced under it. If
// the daemon shuts down, plugins receive Shutdown before the engine
// finishes its own teardown — they are guaranteed to be able to use
// the Daemon during Shutdown for any final cleanup (closing pending
// streams, dispatching final webhook deliveries, etc.).
type Plugin interface {
	// Name returns the registration key of this plugin. Must be
	// stable across releases of the plugin; the daemon engine may
	// use it for keyed lookups, persistence, and operator-facing
	// status output.
	Name() string

	// Init wires the plugin to a running daemon engine. The plugin
	// retains the Daemon for the rest of its lifetime. Init returns
	// an error if the plugin cannot bootstrap; the daemon aborts
	// startup on any plugin Init failure.
	Init(d Daemon) error

	// Shutdown stops the plugin's background work and drains any
	// in-flight requests. The Daemon passed to Init is still valid
	// during Shutdown — plugins may use it for last-mile work — but
	// the daemon engine will not accept new traffic. Shutdown should
	// honor the context's deadline; the daemon will not wait
	// indefinitely on a stuck plugin.
	Shutdown(ctx context.Context) error
}

// Factory builds a new instance of a plugin. Registered factories
// run when the daemon calls LoadAll; each call produces a fresh
// Plugin value, so plugins do not share state across daemon restarts.
type Factory func() Plugin
