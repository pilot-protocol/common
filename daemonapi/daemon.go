// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import (
	"context"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// Daemon is the dependency-free contract a daemon engine exposes to
// plugins. The concrete *daemon.Daemon in web4/pkg/daemon satisfies
// this interface via Go's structural typing — neither side needs to
// import the other.
//
// Every method here exists because at least one plugin (handshake,
// runtime, libpilot) calls it. Adding a method later is a backwards-
// compatible change as long as concrete daemon implementations grow
// the corresponding method first.
//
// Return types deliberately use:
//
//   - Common-package concrete types (*crypto.Identity, *registry.Client,
//     protocol.Addr) — those types already live in the dependency-free
//     common module, so referencing them here doesn't create cycles.
//
//   - daemonapi-local interfaces (Connection, PortAllocator, EventBus,
//     etc.) — where the concrete return type lives inside the daemon
//     engine. The opaque-marker interfaces keep plugins from poking
//     at engine internals while still letting the daemon hand the
//     value back to plugins as a typed token.
type Daemon interface {
	// --- Lifecycle ---------------------------------------------------

	// Start brings the daemon online. Returns when the listeners are
	// bound and the daemon is ready to accept traffic, or with an
	// error if any step of bootstrap fails.
	Start() error

	// Stop drains in-flight work and tears down the daemon. Idempotent;
	// safe to call from a signal handler.
	Stop() error

	// --- Identity ---------------------------------------------------

	// NodeID returns this daemon's stable 32-bit node ID. 0 when the
	// identity has not been loaded yet.
	NodeID() uint32

	// Identity returns the daemon's Ed25519 keypair holder. Returns
	// nil when the daemon was started without an identity file
	// (in-memory tests).
	Identity() *crypto.Identity

	// IdentityPath returns the on-disk path to the identity file.
	// Empty when running in-memory.
	IdentityPath() string

	// Sign signs the message with the local Ed25519 private key.
	// Returns nil when no identity is loaded.
	Sign(msg []byte) []byte

	// --- Configuration ----------------------------------------------

	// AdminToken returns the local admin token used to authenticate
	// privileged registry RPCs. Empty when not configured.
	AdminToken() string

	// TrustAutoApprove reports whether the daemon was started with
	// the auto-approve flag set. Plugins gating user-visible decisions
	// on this flag (handshake auto-accept) read it once at Init.
	TrustAutoApprove() bool

	// --- Network plumbing -------------------------------------------

	// Addr returns the daemon's pilot-network address. Stable for
	// the life of the daemon process.
	Addr() protocol.Addr

	// DialConnection opens an outbound stream to (dstAddr, dstPort)
	// and returns an opaque Connection handle. The handle is passed
	// back to SendData, CloseConnection, NewConnReadWriter, etc.
	DialConnection(dstAddr protocol.Addr, dstPort uint16) (Connection, error)

	// DialConnectionContext is DialConnection with a deadline. The
	// context's Done channel cancels the dial.
	DialConnectionContext(ctx context.Context, dstAddr protocol.Addr, dstPort uint16) (Connection, error)

	// SendData writes the byte slice to the stream connection.
	// Blocks until the data is queued for transmission.
	SendData(conn Connection, data []byte) error

	// SendDatagram sends an unconnected (UDP-shaped) payload to
	// (dstAddr, dstPort). Best-effort, no retransmission.
	SendDatagram(dstAddr protocol.Addr, dstPort uint16, data []byte) error

	// CloseConnection tears down the connection. Idempotent.
	CloseConnection(conn Connection)

	// NewConnReadWriter wraps a stream Connection as a net.Conn-style
	// adapter. Plugins that need read/write semantics use this; the
	// daemon retains ownership of the underlying connection state.
	NewConnReadWriter(conn Connection) ConnReadWriter

	// Ports returns the daemon's port allocator. Opaque to most
	// plugins; usually handed off to other plugins (e.g. handshake)
	// that bind well-known ports through it.
	Ports() PortAllocator

	// Tunnels returns the daemon's tunnel registry. Opaque to most
	// plugins.
	Tunnels() TunnelRegistry

	// --- Registry ---------------------------------------------------

	// RegistryClient returns the L8 registry-side-channel client.
	// nil when the daemon is running without a registry connection.
	RegistryClient() *registry.Client

	// RegConnListNodes is the privileged list_nodes RPC, used by the
	// policy plugin to enumerate per-network members.
	RegConnListNodes(netID uint16, token string) (map[string]any, error)

	// SetMemberTags updates the local node's per-network tag list
	// via the registry.
	SetMemberTags(netID uint16, tags []string)

	// --- Events -----------------------------------------------------

	// PublishEvent is the bus.Publish wrapper, exposed at top level
	// because plugins commonly publish without holding a Bus reference.
	PublishEvent(topic string, payload map[string]any)

	// Bus returns the in-process event bus for plugins that subscribe.
	Bus() EventBus

	// --- Trust + handshake plugin coordination ----------------------

	// GetTrustChecker returns the currently-registered trust checker
	// (typically the trustedagents plugin). Returns nil when no
	// checker is wired.
	GetTrustChecker() TrustChecker

	// RegisterTrustChecker installs the given checker as the daemon's
	// trust authority. Called once at startup by the trustedagents
	// plugin via the runtime adapter.
	RegisterTrustChecker(tc TrustChecker)

	// HandshakeService returns the currently-registered handshake
	// service. Returns nil when no handshake plugin is wired (tests
	// that bypass plugins).
	HandshakeService() HandshakeService

	// RegisterHandshakeService installs the handshake plugin's
	// service. Called once at startup via the runtime adapter.
	RegisterHandshakeService(svc HandshakeService)

	// TrustedPeers proxies through to HandshakeService().TrustedPeers().
	// Returns nil when no handshake plugin is wired.
	TrustedPeers() []HandshakeTrustRecord

	// HandshakeRevokeTrust proxies through to HandshakeService().RevokeTrust.
	HandshakeRevokeTrust(nodeID uint32) error

	// HandshakeSendRequest proxies through to HandshakeService().SendRequest.
	HandshakeSendRequest(nodeID uint32, reason string) error

	// --- Policy + webhook plugin coordination -----------------------

	// RegisterPolicyManager installs the policy plugin's manager.
	RegisterPolicyManager(pm PolicyManager)

	// SetWebhookURL hot-swaps the active webhook URL on the registered
	// webhook plugin. No-op when no plugin is registered.
	SetWebhookURL(url string)

	// RegisterWebhookManager installs the webhook plugin's manager.
	RegisterWebhookManager(wm WebhookManager)
}
