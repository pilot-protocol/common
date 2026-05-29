// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import "github.com/pilot-protocol/common/protocol"

// Connection is the daemon-facing handle to a stream connection.
// Plugins receive Connection values from DialConnection / Accept and
// pass them back to SendData / CloseConnection / NewConnReadWriter.
//
// The Info accessor returns a struct snapshot of the four endpoint
// quantities a plugin commonly needs (local/remote address + port).
// This avoids exposing every field of the concrete *daemon.Connection
// through the interface, and avoids name collisions between Go's
// exported struct fields and same-named methods on the interface.
type Connection interface {
	// Info returns an endpoint snapshot. The returned struct is a
	// value copy, so plugins may hold it across goroutines.
	Info() ConnectionInfo
}

// ConnectionInfo is the endpoint snapshot returned by Connection.Info.
type ConnectionInfo struct {
	LocalAddr  protocol.Addr
	LocalPort  uint16
	RemoteAddr protocol.Addr
	RemotePort uint16
}

// ConnReadWriter is the read/write adapter plugins use when they
// need net.Conn-style I/O on a Connection. Construct one via
// Daemon.NewConnReadWriter(conn).
type ConnReadWriter interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Listener is a bound port that yields inbound Connection values
// via Accept. Plugins (notably handshake on PortHandshake) hold a
// Listener for the lifetime of their server loop.
type Listener interface {
	// Accept blocks until an inbound Connection lands on the
	// listener or the listener is closed. ok=false signals close
	// (no further Connections will arrive).
	Accept() (conn Connection, ok bool)

	// Port returns the bound port. Stable for the listener's lifetime.
	Port() uint16

	// Close releases the port and stops accepting new Connections.
	Close() error
}

// PortAllocator is the daemon's port table. Plugins receive it via
// Daemon.Ports() and bind / unbind well-known ports through it. The
// concrete *daemon.PortManager satisfies this via structural typing.
type PortAllocator interface {
	// Bind takes ownership of the given port and returns a Listener
	// that will receive Connections targeting it. Returns an error
	// if the port is already bound.
	Bind(port uint16) (Listener, error)

	// Unbind releases the port. The Listener returned by Bind also
	// stops accepting (its Accept loop returns ok=false). Idempotent;
	// unbinding an unbound port is a no-op.
	Unbind(port uint16)
}

// TunnelRegistry is the daemon's tunnel table. Plugins use RemovePeer
// to tear down a peer's tunnel state when revoking trust or closing
// a connection. The concrete *daemon.TunnelManager satisfies this
// via structural typing.
type TunnelRegistry interface {
	// RemovePeer tears down the encrypted tunnel for the given peer.
	// All per-peer state (session keys, retransmit queues, routing
	// entries) is dropped. Safe to call when no tunnel exists.
	RemovePeer(nodeID uint32)
}
