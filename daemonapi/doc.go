// SPDX-License-Identifier: AGPL-3.0-or-later

// Package daemonapi is the dependency-free contract layer between the
// daemon engine and its plugins.
//
// The cycle problem: handshake / runtime / libpilot are daemon plugins
// that historically imported web4/pkg/daemon for the concrete Daemon
// struct, Config, Connection, Listener, and assorted services. The
// daemon binary in turn imported the plugins to compose itself. This
// is a real cycle (web4 ↔ plugins) that survives only because of
// `replace` directives during local dev.
//
// daemonapi breaks the cycle by hosting:
//
//   1. Pure-interface contracts (Daemon, Connection, Listener,
//      TrustChecker, HandshakeService, PolicyManager, PolicyRunner,
//      WebhookManager, ...). The concrete *daemon.Daemon and its
//      members satisfy these via Go's structural typing — the daemon
//      engine never imports daemonapi to register, and plugins never
//      import the daemon engine.
//
//   2. A runtime plugin lifecycle (Plugin interface) and a process-
//      global registry (RegisterPlugin, LoadAll). Plugins register
//      themselves from an init() block in their own package; the
//      daemon engine, with no compile-time knowledge of which plugins
//      exist, iterates whatever the registry contains.
//
// "Not static" wiring means:
//
//   - The daemon engine has zero hardcoded list of plugins. Adding or
//     removing a plugin from a binary is a single blank-import line
//     in cmd/daemon/main.go; the daemon, plugin, and other plugin
//     packages all stay unchanged.
//
//   - The Plugin contract is interface-based, so a plugin's source
//     code is interchangeable: two `handshake` implementations satisfy
//     the same Plugin interface, the daemon doesn't know the difference.
//
//   - The registration mechanism is identical for in-process plugins
//     (Go packages linked into the binary) and for true runtime
//     plugins (Go plugin.Open of .so files). The .so's init() block
//     calls RegisterPlugin the same way; the daemon engine then
//     iterates the registry.
//
// What this package does NOT do:
//
//   - It does not own daemon implementation code. Concrete types stay
//     in web4/pkg/daemon (and plugins' own implementations stay in
//     their own repos). Interfaces only.
//
//   - It does not specify how the daemon engine starts or shuts down.
//     That's the daemon's job. The Plugin lifecycle methods (Init,
//     Shutdown) tell plugins when the daemon is ready and when it's
//     stopping; the daemon decides the broader sequencing.
package daemonapi
