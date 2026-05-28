// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

// Connection is an opaque handle to a daemon stream connection.
// Plugins receive Connection values from DialConnection / Accept and
// pass them back to SendData / CloseConnection / NewConnReadWriter.
// The concrete *daemon.Connection in web4/pkg/daemon satisfies this
// via Go's structural typing — there are no methods on the interface
// itself; it's a marker token.
//
// Keeping Connection an opaque marker is deliberate: plugins like
// runtime treat connections as values they hand back to the daemon
// for any operation. They never inspect connection internals.
// Anything that ever does (writing bytes, reading bytes, closing)
// goes through ConnReadWriter — see below.
type Connection interface{}

// ConnReadWriter is the read/write adapter plugins use when they
// need net.Conn-style I/O on a Connection. Construct one via
// Daemon.NewConnReadWriter(conn).
type ConnReadWriter interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// PortAllocator is an opaque handle to the daemon's port table.
// Plugins receive it via Daemon.Ports() and typically hand it to
// other plugins that need to bind well-known ports. Like Connection,
// it has no methods on this interface — concrete daemon types
// satisfy it via structural typing.
type PortAllocator interface{}

// TunnelRegistry is an opaque handle to the daemon's tunnel table.
// Same opaque-marker shape as PortAllocator: plugins pass it
// around, the daemon owns the implementation.
type TunnelRegistry interface{}
