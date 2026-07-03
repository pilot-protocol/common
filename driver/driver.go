// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// DefaultSocketPath returns the default Unix socket path for IPC.
// On Linux it prefers $XDG_RUNTIME_DIR (typically /run/user/<uid>,
// which is private to the user); falls back to /tmp/pilot.sock.
// On macOS /tmp is already per-user via SIP, so /tmp/pilot.sock is safe.
func DefaultSocketPath() string {
	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			return filepath.Join(xdg, "pilot.sock")
		}
	}
	return "/tmp/pilot.sock"
}

// defaultDialTimeout bounds DialAddr / Listen / Broadcast so a wedged or
// non-responsive daemon can't block the caller forever. The daemon resolves
// + dials within this window in the normal case (direct punch or relay
// fallback both complete well under it); callers needing a tighter bound use
// DialAddrTimeout. Operations that legitimately block in the daemon
// (WaitForTrust) deliberately keep the unbounded sendAndWait path.
const defaultDialTimeout = 30 * time.Second

// Handshake sub-commands (must match daemon SubHandshake* constants)
const (
	subHandshakeSend    byte = 0x01
	subHandshakeApprove byte = 0x02
	subHandshakeReject  byte = 0x03
	subHandshakePending byte = 0x04
	subHandshakeTrusted byte = 0x05
	subHandshakeRevoke  byte = 0x06
	subHandshakeWait    byte = 0x07
)

// jsonRPC sends an IPC message, waits for the expected response, and
// unmarshals the JSON payload. Most driver methods follow this pattern.
func (d *Driver) jsonRPC(msg []byte, expectCmd byte, label string) (map[string]interface{}, error) {
	resp, err := d.ipc.sendAndWait(msg, expectCmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("%s unmarshal: %w", label, err)
	}
	return result, nil
}

// Driver is the main entry point for the Pilot Protocol SDK.
type Driver struct {
	ipc        *ipcClient
	socketPath string
}

// Connect creates a new driver connected to the local daemon.
func Connect(socketPath string) (*Driver, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath()
	}

	ipc, err := newIPCClient(socketPath)
	if err != nil {
		return nil, err
	}

	return &Driver{ipc: ipc, socketPath: socketPath}, nil
}

// Dial opens a stream connection to a remote address:port.
// addr format: "N:XXXX.YYYY.YYYY:PORT"
func (d *Driver) Dial(addr string) (*Conn, error) {
	sa, err := protocol.ParseSocketAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	return d.DialAddr(sa.Addr, sa.Port)
}

// DialAddr opens a stream connection to a remote Addr + port. It applies
// defaultDialTimeout so a non-responsive daemon cannot block the caller
// indefinitely; use DialAddrTimeout to supply an explicit bound.
func (d *Driver) DialAddr(dst protocol.Addr, port uint16) (*Conn, error) {
	return d.DialAddrTimeout(dst, port, defaultDialTimeout)
}

// DialAddrTimeout opens a stream connection with a client-side timeout.
// If the daemon does not respond within the timeout, the dial is cancelled.
func (d *Driver) DialAddrTimeout(dst protocol.Addr, port uint16, timeout time.Duration) (*Conn, error) {
	msg := make([]byte, 1+protocol.AddrSize+2)
	msg[0] = cmdDial
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)

	resp, err := d.ipc.sendAndWaitTimeout(msg, cmdDialOK, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("invalid dial response")
	}

	connID := binary.BigEndian.Uint32(resp[0:4])
	recvCh := d.ipc.registerRecvCh(connID)

	return &Conn{
		id:         connID,
		remoteAddr: protocol.SocketAddr{Addr: dst, Port: port},
		ipc:        d.ipc,
		recvCh:     recvCh,
		deadlineCh: make(chan struct{}),
	}, nil
}

// Listen binds a port and returns a Listener that accepts connections.
func (d *Driver) Listen(port uint16) (*Listener, error) {
	msg := make([]byte, 3)
	msg[0] = cmdBind
	binary.BigEndian.PutUint16(msg[1:3], port)

	resp, err := d.ipc.sendAndWaitTimeout(msg, cmdBindOK, defaultDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	boundPort := binary.BigEndian.Uint16(resp[0:2])

	// H12 fix: register per-port accept channel
	acceptCh := d.ipc.registerAcceptCh(boundPort)

	return &Listener{
		port:     boundPort,
		ipc:      d.ipc,
		acceptCh: acceptCh,
		done:     make(chan struct{}),
	}, nil
}

// SendTo sends an unreliable unicast datagram to the given address:port.
// Broadcast addresses (Node=0xFFFFFFFF) are not accepted on this path; use
// Broadcast, which requires the daemon's admin token.
//
// Send semantics: this is fire-and-forget. A nil return means only that the
// frame was successfully enqueued to the local daemon over IPC — it does NOT
// indicate the datagram was transmitted on the wire, routed, or delivered to
// the peer. Datagrams are unreliable; there is no acknowledgement. The only
// errors reported are local IPC failures (empty/oversized frame, socket
// write error).
func (d *Driver) SendTo(dst protocol.Addr, port uint16, data []byte) error {
	if dst.IsBroadcast() {
		return fmt.Errorf("broadcast address requires admin token: use Driver.Broadcast")
	}
	msg := make([]byte, 1+protocol.AddrSize+2+len(data))
	msg[0] = cmdSendTo
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)
	copy(msg[1+protocol.AddrSize+2:], data)
	return d.ipc.send(msg)
}

// Broadcast fans an unreliable datagram out to every member of a network.
// The admin token must match the daemon's configured Config.AdminToken; an
// empty token or mismatched token is rejected. Permitted on every network
// including network 0 (backbone). Sender membership is not required.
func (d *Driver) Broadcast(netID uint16, port uint16, data []byte, adminToken string) error {
	tokenBytes := []byte(adminToken)
	msg := make([]byte, 1+2+2+2+len(tokenBytes)+len(data))
	msg[0] = cmdBroadcast
	binary.BigEndian.PutUint16(msg[1:3], netID)
	binary.BigEndian.PutUint16(msg[3:5], port)
	binary.BigEndian.PutUint16(msg[5:7], uint16(len(tokenBytes)))
	copy(msg[7:7+len(tokenBytes)], tokenBytes)
	copy(msg[7+len(tokenBytes):], data)
	if _, err := d.ipc.sendAndWaitTimeout(msg, cmdBroadcastOK, defaultDialTimeout); err != nil {
		return err
	}
	return nil
}

// RecvFrom receives the next incoming datagram.
func (d *Driver) RecvFrom() (*Datagram, error) {
	dg, ok := <-d.ipc.dgCh
	if !ok {
		return nil, fmt.Errorf("driver closed")
	}
	return dg, nil
}

// Info returns the daemon's status information.
func (d *Driver) Info() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdInfo}, cmdInfoOK, "info")
}

// Health returns a lightweight health check from the daemon.
func (d *Driver) Health() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHealth}, cmdHealthOK, "health")
}

// Handshake sends a trust handshake request to a remote node.
func (d *Driver) Handshake(nodeID uint32, justification string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(justification))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeSend
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], justification)
	return d.jsonRPC(msg, cmdHandshakeOK, "handshake")
}

// ApproveHandshake approves a pending trust handshake request.
func (d *Driver) ApproveHandshake(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeApprove
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "approve")
}

// RejectHandshake rejects a pending trust handshake request.
func (d *Driver) RejectHandshake(nodeID uint32, reason string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(reason))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeReject
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], reason)
	return d.jsonRPC(msg, cmdHandshakeOK, "reject")
}

// PendingHandshakes returns pending trust handshake requests.
func (d *Driver) PendingHandshakes() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakePending}, cmdHandshakeOK, "pending")
}

// WaitForTrust blocks (in the daemon) until the peer transitions to trusted
// or the timeout elapses. Single IPC roundtrip — the daemon-side
// HandshakeService.WaitForTrust waits on a per-node channel that is closed
// the moment trust is granted, so wakeup latency is sub-millisecond.
//
// Backward compatibility: an old daemon (no SubHandshakeWait) returns an
// "unknown sub-command" error; callers should treat that as "wait skipped"
// and proceed.
func (d *Driver) WaitForTrust(nodeID uint32, timeoutMs uint32) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+4)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeWait
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	binary.BigEndian.PutUint32(msg[6:10], timeoutMs)
	return d.jsonRPC(msg, cmdHandshakeOK, "wait")
}

// TrustedPeers returns all trusted peers from the handshake protocol.
func (d *Driver) TrustedPeers() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakeTrusted}, cmdHandshakeOK, "trusted")
}

// RevokeTrust removes a peer from the trusted set and notifies the registry.
func (d *Driver) RevokeTrust(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeRevoke
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "revoke")
}

// PreferDirect asks the daemon to drop the existing tunnel to the peer
// and any sticky routing state (cached endpoint, cached resolve, unpinned
// relay flag), then re-resolve from the registry and prefer a direct UDP
// path on the next dial. Returns the new routing state the daemon arrived
// at — typically {"node_id": N, "relay_active": false, "pinned": false,
// "real_addr": "..."} when a direct path was found, or relay_active=true
// when the registry's relay_only flag is authoritative or the punch
// failed.
//
// Useful when stream traffic (pilotctl send-file) is failing on a relay
// path while small UDP (pilotctl ping) still works — typical symptom of
// a beacon-mediated tunnel that established once and then stuck.
//
// Backward compatibility: an old daemon (no CmdPreferDirect) returns an
// "unknown command" error — callers should treat that as "best-effort
// hint" and proceed with the normal dial, not abort the operation.
func (d *Driver) PreferDirect(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 5)
	msg[0] = cmdPreferDirect
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	return d.jsonRPC(msg, cmdPreferDirectOK, "prefer_direct")
}

// ResolveHostname resolves a hostname to node info via the daemon.
func (d *Driver) ResolveHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdResolveHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdResolveHostnameOK, "resolve_hostname")
}

// SetHostname sets or clears the daemon's hostname via the registry.
func (d *Driver) SetHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdSetHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdSetHostnameOK, "set_hostname")
}

// SetVisibility sets the daemon's visibility on the registry.
func (d *Driver) SetVisibility(public bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetVisibility
	if public {
		msg[1] = 1
	}
	return d.jsonRPC(msg, cmdSetVisibilityOK, "set_visibility")
}

// Deregister removes the daemon from the registry.
func (d *Driver) Deregister() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdDeregister}, cmdDeregisterOK, "deregister")
}

// SetTags sets the capability tags for this daemon's node.
func (d *Driver) SetTags(tags []string) (map[string]interface{}, error) {
	data, _ := json.Marshal(tags)
	msg := make([]byte, 1+len(data))
	msg[0] = cmdSetTags
	copy(msg[1:], data)
	return d.jsonRPC(msg, cmdSetTagsOK, "set_tags")
}

// SetWebhook sets or clears the daemon's webhook URL at runtime.
// An empty URL disables the webhook.
func (d *Driver) SetWebhook(url string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(url))
	msg[0] = cmdSetWebhook
	copy(msg[1:], url)
	return d.jsonRPC(msg, cmdSetWebhookOK, "set_webhook")
}

// RotateKey asks the daemon to rotate its Ed25519 identity at the registry.
// The daemon generates a new keypair, signs proof of the current key, calls
// registry.RotateKey, then atomically swaps and persists the new identity.
func (d *Driver) RotateKey() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdRotateKey}, cmdRotateKeyOK, "rotate_key")
}

// SubmitBadge attaches a verified-address badge to this node's registry
// entry. badge and badgeSig are produced out-of-band by the verifier
// sidecar; the daemon signs proof of the current key over the badge before
// forwarding to the registry, which also verifies the badge offline against
// the pinned issuer key. Verification is optional — nodes without a badge
// keep working unchanged.
func (d *Driver) SubmitBadge(badge, badgeSig string) (map[string]interface{}, error) {
	data, _ := json.Marshal(map[string]string{"badge": badge, "badge_sig": badgeSig})
	msg := make([]byte, 1+len(data))
	msg[0] = cmdSubmitBadge
	copy(msg[1:], data)
	return d.jsonRPC(msg, cmdSubmitBadgeOK, "submit_badge")
}

// EnrollRecovery records this node's opaque recovery commitment so the
// address can later be recovered if the current key is lost. enrollment and
// enrollmentSig come from the verifier sidecar; the daemon signs proof of the
// current key over the commitment before forwarding to the registry. The
// raw external identity never leaves the verifier — only the commitment.
func (d *Driver) EnrollRecovery(enrollment, enrollmentSig string) (map[string]interface{}, error) {
	data, _ := json.Marshal(map[string]string{"enrollment": enrollment, "enrollment_sig": enrollmentSig})
	msg := make([]byte, 1+len(data))
	msg[0] = cmdEnrollRecovery
	copy(msg[1:], data)
	return d.jsonRPC(msg, cmdEnrollRecoveryOK, "enroll_recovery")
}

const (
	// maxEnvelopeLen bounds a canonical reqsig envelope; real envelopes
	// are <200 bytes (12-char domain, 12 hex addr, decimal ts, 16 hex
	// nonce, 64 hex hash, <=64 char audience, 5 pipes).
	maxEnvelopeLen = 512
	// maxSigB64Len bounds a base64 ed25519 signature (88 chars).
	maxSigB64Len = 128
)

// SignEnvelope asks the daemon to sign a request-signature envelope
// (common/reqsig) for the given audience over the given body hash (64
// lowercase hex chars — sha256 of the request body, see reqsig.HashBody).
// The daemon constructs the envelope itself — its own address, the current
// timestamp, a fresh nonce — and signs only the reqsig canonical form; it
// never signs caller-supplied raw strings. Returns {envelope, signature,
// address}.
func (d *Driver) SignEnvelope(audience, bodyHash string) (map[string]interface{}, error) {
	if len(bodyHash) != 64 {
		return nil, fmt.Errorf("sign_envelope: body hash must be 64 hex chars (sha256)")
	}
	if audience == "" || len(audience) > 64 {
		return nil, fmt.Errorf("sign_envelope: audience must be 1-64 chars")
	}
	data, _ := json.Marshal(map[string]string{"audience": audience, "body_hash": bodyHash})
	msg := append([]byte{cmdSignEnvelope}, data...)
	return d.jsonRPC(msg, cmdSignEnvelopeOK, "sign_envelope")
}

// VerifyEnvelope checks a canonical reqsig envelope + base64 signature via
// the daemon, which resolves the claimed node's key from its local cache
// first and the registry on miss. With checkStanding the daemon also reports
// the signer's registry standing (online, last_seen_unix, key_generation,
// network_member) when the registry provides it. A failed check is NOT an
// error — the reply carries valid=false plus a reason.
func (d *Driver) VerifyEnvelope(envelope, sigB64 string, checkStanding bool) (map[string]interface{}, error) {
	return d.VerifyEnvelopeMaxSkew(envelope, sigB64, checkStanding, 0)
}

// VerifyEnvelopeMaxSkew is VerifyEnvelope with an explicit freshness window
// in seconds. 0 selects the daemon default (reqsig.DefaultMaxSkew).
func (d *Driver) VerifyEnvelopeMaxSkew(envelope, sigB64 string, checkStanding bool, maxSkewSecs uint32) (map[string]interface{}, error) {
	// Canonical envelopes are <200 bytes and a base64 ed25519 signature is
	// 88 chars; bounding both rejects garbage client-side and keeps the
	// request frame allocation size independent of caller input.
	if envelope == "" || len(envelope) > maxEnvelopeLen {
		return nil, fmt.Errorf("verify_envelope: envelope must be 1-%d bytes", maxEnvelopeLen)
	}
	if sigB64 == "" || len(sigB64) > maxSigB64Len {
		return nil, fmt.Errorf("verify_envelope: signature must be 1-%d bytes", maxSigB64Len)
	}
	data, _ := json.Marshal(map[string]interface{}{
		"envelope":       envelope,
		"signature":      sigB64,
		"check_standing": checkStanding,
		"max_skew_secs":  maxSkewSecs,
	})
	msg := append([]byte{cmdVerifyEnvelope}, data...)
	return d.jsonRPC(msg, cmdVerifyEnvelopeOK, "verify_envelope")
}

// Disconnect closes a connection by ID. Used by administrative tools.
// Fire-and-forget: the daemon always responds CmdCloseOK regardless of
// whether the connID exists, so there is no error to propagate. Using
// sendAndWait here would corrupt a concurrent sendAndWait for a different
// command if a server-pushed cmdCloseOK (remote FIN) arrived simultaneously.
func (d *Driver) Disconnect(connID uint32) error {
	msg := make([]byte, 5)
	msg[0] = cmdClose
	binary.BigEndian.PutUint32(msg[1:5], connID)
	return d.ipc.send(msg)
}

// NetworkList returns all networks known to the registry.
func (d *Driver) NetworkList() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdNetwork, subNetworkList}, cmdNetworkOK, "network list")
}

// NetworkJoin joins a network by ID, optionally using a token for token-gated networks.
func (d *Driver) NetworkJoin(networkID uint16, token string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+2+len(token))
	msg[0] = cmdNetwork
	msg[1] = subNetworkJoin
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	copy(msg[4:], token)
	return d.jsonRPC(msg, cmdNetworkOK, "network join")
}

// NetworkLeave leaves a network by ID.
func (d *Driver) NetworkLeave(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdNetwork
	msg[1] = subNetworkLeave
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdNetworkOK, "network leave")
}

// NetworkMembers lists all members of a network.
func (d *Driver) NetworkMembers(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdNetwork
	msg[1] = subNetworkMembers
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdNetworkOK, "network members")
}

// NetworkInvite invites a target node to a network (requires admin token on daemon).
func (d *Driver) NetworkInvite(networkID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 8)
	msg[0] = cmdNetwork
	msg[1] = subNetworkInvite
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	binary.BigEndian.PutUint32(msg[4:8], targetNodeID)
	return d.jsonRPC(msg, cmdNetworkOK, "network invite")
}

// NetworkPollInvites returns pending network invites for this node.
func (d *Driver) NetworkPollInvites() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdNetwork, subNetworkPollInvites}, cmdNetworkOK, "network poll-invites")
}

// NetworkRespondInvite accepts or rejects a pending network invite.
func (d *Driver) NetworkRespondInvite(networkID uint16, accept bool) (map[string]interface{}, error) {
	msg := make([]byte, 5)
	msg[0] = cmdNetwork
	msg[1] = subNetworkRespondInvite
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	if accept {
		msg[4] = 1
	}
	return d.jsonRPC(msg, cmdNetworkOK, "network respond-invite")
}

// ManagedStatus returns the status of a managed network engine.
func (d *Driver) ManagedStatus(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedStatus
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed status")
}

// ManagedForceCycle forces a prune/fill cycle in a managed network.
func (d *Driver) ManagedForceCycle(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedCycle
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed cycle")
}

// ManagedReconcile asks the daemon's policy runner for networkID to
// poll the registry and refresh its peer set — without running a
// policy cycle. Returns {network_id, peers}.
func (d *Driver) ManagedReconcile(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedReconcile
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed reconcile")
}

// PolicyGet retrieves the active policy for a network from the daemon.
func (d *Driver) PolicyGet(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x00 // get
	// Shift: need [cmd][sub][action][netID_hi][netID_lo]
	msg = make([]byte, 5)
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x00 // get
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "policy get")
}

// PolicySet sends a policy document to the daemon for immediate application.
// adminToken authenticates the caller as a network administrator —
// pilot-daemon's managed.policy.set IPC handler validates this against
// its configured AdminToken before applying the policy. Empty token is
// accepted by the daemon iff it has no AdminToken configured (default
// solo-mode daemons); managed-mode daemons reject empty tokens.
// (PILOT-233)
func (d *Driver) PolicySet(networkID uint16, policyJSON []byte, adminToken string) (map[string]interface{}, error) {
	// Wire: [cmd][sub][action=0x01][netID(2)][tokenLen(2)][token...][policyJSON...]
	tokenLen := len(adminToken)
	msg := make([]byte, 7+tokenLen+len(policyJSON))
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x01 // set
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	binary.BigEndian.PutUint16(msg[5:7], uint16(tokenLen))
	copy(msg[7:7+tokenLen], []byte(adminToken))
	copy(msg[7+tokenLen:], policyJSON)
	return d.jsonRPC(msg, cmdManagedOK, "policy set")
}

// MemberTagsGet retrieves admin-assigned member tags for a node in a network.
func (d *Driver) MemberTagsGet(networkID uint16, nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 9)
	msg[0] = cmdManaged
	msg[1] = subManagedMemberTags
	msg[2] = 0x00 // get
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	return d.jsonRPC(msg, cmdManagedOK, "member-tags get")
}

// MemberTagsSet sets admin-assigned member tags for a node in a network.
func (d *Driver) MemberTagsSet(networkID uint16, nodeID uint32, tags []string) (map[string]interface{}, error) {
	tagsJSON, _ := json.Marshal(tags)
	msg := make([]byte, 9+len(tagsJSON))
	msg[0] = cmdManaged
	msg[1] = subManagedMemberTags
	msg[2] = 0x01 // set
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	copy(msg[9:], tagsJSON)
	return d.jsonRPC(msg, cmdManagedOK, "member-tags set")
}

// Close disconnects from the daemon.
func (d *Driver) Close() error {
	return d.ipc.close()
}
