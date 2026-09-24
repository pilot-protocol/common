// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pilot-protocol/common/registry/wire"
)

// BinaryClient talks to a registry server using the binary wire protocol.
// It provides native binary encoding for hot-path operations (heartbeat, lookup,
// resolve) and JSON-over-binary passthrough for all other operations.
type BinaryClient struct {
	conn   net.Conn
	mu     sync.Mutex
	addr   string
	closed bool
	dial   DialContextFunc // optional; see WithDialer

	// closeOnce makes Close idempotent; done (created lazily by doneCh)
	// is closed by Close to wake a reconnect backoff, which runs with mu
	// held.
	closeOnce sync.Once
	doneOnce  sync.Once
	done      chan struct{}
}

// DialBinary connects to a registry server and negotiates the binary wire protocol.
// The server detects the magic bytes and switches to binary mode for this connection.
// Pass WithDialer to route the connection (and every reconnect) through a
// custom dialer such as an HTTP CONNECT proxy.
func DialBinary(addr string, opts ...DialOption) (*BinaryClient, error) {
	o := applyDialOptions(opts)
	conn, err := dialConn(context.Background(), o.dial, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("dial registry: %w", err)
	}

	// Send magic + version to negotiate binary protocol
	var handshake [5]byte
	copy(handshake[:4], wire.Magic[:])
	handshake[4] = wire.Version
	if _, err := conn.Write(handshake[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("binary handshake: %w", err)
	}

	return &BinaryClient{conn: conn, addr: addr, dial: o.dial}, nil
}

// Close shuts down the binary client connection. It is idempotent: the
// teardown runs once, later calls return nil, and every call after Close
// returns an error matching ErrClosed.
func (c *BinaryClient) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		// Wake a reconnect backoff first: it holds c.mu.
		close(c.doneCh())
		c.mu.Lock()
		c.closed = true
		conn := c.conn
		c.mu.Unlock()
		if conn != nil {
			if cerr := conn.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
				err = cerr
			}
		}
	})
	return err
}

func (c *BinaryClient) doneCh() chan struct{} {
	c.doneOnce.Do(func() { c.done = make(chan struct{}) })
	return c.done
}

// closedLocked reports whether Close has started. Must be called with c.mu held.
func (c *BinaryClient) closedLocked() bool {
	if c.closed {
		return true
	}
	select {
	case <-c.doneCh():
		return true
	default:
		return false
	}
}

// Addr returns the registry address this client is connected to.
func (c *BinaryClient) Addr() string {
	return c.addr
}

// reconnect re-establishes the binary connection after cause broke it.
// Must be called with c.mu held.
func (c *BinaryClient) reconnect(cause error) error {
	if c.closedLocked() {
		return ErrClosed
	}
	if c.conn != nil {
		c.conn.Close()
		// Retired: a failed redial leaves no conn for Close to close twice.
		c.conn = nil
	}

	backoff := defaultReconnectPolicy.dialBase
	var lastErr error

	for attempts := 0; attempts < maxReconnectAttempts; attempts++ {
		if attempts > 0 {
			// Close wakes this wait (it cannot take c.mu while we sleep).
			if err := sleepCtx(context.Background(), c.doneCh(), jitter(backoff)); err != nil {
				return err
			}
			if backoff *= 2; backoff > defaultReconnectPolicy.dialMax {
				backoff = defaultReconnectPolicy.dialMax
			}
		}
		conn, err := dialConn(context.Background(), c.dial, c.addr, nil)
		if err != nil {
			lastErr = err
			slog.Warn("binary client reconnect failed", "attempt", attempts+1, "err", err, "cause", errText(cause))
			continue
		}

		// Re-negotiate binary protocol
		var handshake [5]byte
		copy(handshake[:4], wire.Magic[:])
		handshake[4] = wire.Version
		if _, err := conn.Write(handshake[:]); err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		if c.closedLocked() {
			// Close started while we were dialing and waits for c.mu.
			conn.Close()
			return ErrClosed
		}
		c.conn = conn
		slog.Info("binary client reconnected", "addr", c.addr, "cause", errText(cause))
		return nil
	}
	return fmt.Errorf("reconnect failed after %d attempts: %w", maxReconnectAttempts, lastErr)
}

// Heartbeat sends a binary heartbeat and returns the server time and key expiry warning.
func (c *BinaryClient) Heartbeat(nodeID uint32, sig []byte) (unixTime int64, keyExpiryWarning bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedLocked() {
		return 0, false, ErrClosed
	}

	unixTime, keyExpiryWarning, err = c.heartbeatLocked(nodeID, sig)
	if err != nil && !c.closedLocked() {
		// Connection-level failure — reconnect and retry once
		if reconnErr := c.reconnect(err); reconnErr != nil {
			return 0, false, binaryReconnectFailed("heartbeat", err, reconnErr)
		}
		unixTime, keyExpiryWarning, err = c.heartbeatLocked(nodeID, sig)
	}
	return
}

// binaryReconnectFailed keeps both the request error and the reconnect
// error in the chain.
func binaryReconnectFailed(op string, err, reconnErr error) error {
	if errors.Is(reconnErr, ErrClosed) {
		return closedDuring(err)
	}
	return fmt.Errorf("%s failed and reconnect failed: %w (reconnect: %w)", op, err, reconnErr)
}

func (c *BinaryClient) heartbeatLocked(nodeID uint32, sig []byte) (int64, bool, error) {
	if c.conn == nil {
		return 0, false, errNotConnected
	}
	if err := wire.WriteFrame(c.conn, wire.MsgHeartbeat, wire.EncodeHeartbeatReq(nodeID, sig)); err != nil {
		return 0, false, fmt.Errorf("send heartbeat: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, payload, err := wire.ReadFrame(c.conn)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, false, fmt.Errorf("recv heartbeat: %w", err)
	}

	if msgType == wire.MsgError {
		return 0, false, fmt.Errorf("registry: %s", wire.DecodeError(payload))
	}
	if msgType != wire.MsgHeartbeatOK {
		return 0, false, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	return wire.DecodeHeartbeatResp(payload)
}

// Lookup sends a binary lookup request and returns the decoded result.
func (c *BinaryClient) Lookup(nodeID uint32) (*wire.LookupResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedLocked() {
		return nil, ErrClosed
	}

	result, err := c.lookupLocked(nodeID)
	if err != nil && !c.closedLocked() {
		if reconnErr := c.reconnect(err); reconnErr != nil {
			return nil, binaryReconnectFailed("lookup", err, reconnErr)
		}
		result, err = c.lookupLocked(nodeID)
	}
	return result, err
}

func (c *BinaryClient) lookupLocked(nodeID uint32) (*wire.LookupResult, error) {
	if c.conn == nil {
		return nil, errNotConnected
	}
	if err := wire.WriteFrame(c.conn, wire.MsgLookup, wire.EncodeLookupReq(nodeID)); err != nil {
		return nil, fmt.Errorf("send lookup: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, payload, err := wire.ReadFrame(c.conn)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("recv lookup: %w", err)
	}

	if msgType == wire.MsgError {
		return nil, fmt.Errorf("registry: %s", wire.DecodeError(payload))
	}
	if msgType != wire.MsgLookupOK {
		return nil, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	result, err := wire.DecodeLookupResp(payload)
	if err != nil {
		return nil, fmt.Errorf("decode lookup response: %w", err)
	}
	return &result, nil
}

// Resolve sends a binary resolve request and returns the decoded result.
func (c *BinaryClient) Resolve(nodeID, requesterID uint32, sig []byte) (*wire.ResolveResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedLocked() {
		return nil, ErrClosed
	}

	result, err := c.resolveLocked(nodeID, requesterID, sig)
	if err != nil && !c.closedLocked() {
		if reconnErr := c.reconnect(err); reconnErr != nil {
			return nil, binaryReconnectFailed("resolve", err, reconnErr)
		}
		result, err = c.resolveLocked(nodeID, requesterID, sig)
	}
	return result, err
}

func (c *BinaryClient) resolveLocked(nodeID, requesterID uint32, sig []byte) (*wire.ResolveResult, error) {
	if c.conn == nil {
		return nil, errNotConnected
	}
	if err := wire.WriteFrame(c.conn, wire.MsgResolve, wire.EncodeResolveReq(nodeID, requesterID, sig)); err != nil {
		return nil, fmt.Errorf("send resolve: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, payload, err := wire.ReadFrame(c.conn)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("recv resolve: %w", err)
	}

	if msgType == wire.MsgError {
		return nil, fmt.Errorf("registry: %s", wire.DecodeError(payload))
	}
	if msgType != wire.MsgResolveOK {
		return nil, fmt.Errorf("unexpected response type 0x%02x", msgType)
	}

	result, err := wire.DecodeResolveResp(payload)
	if err != nil {
		return nil, fmt.Errorf("decode resolve response: %w", err)
	}
	return &result, nil
}

// SendJSON sends a JSON message over the binary protocol using JSON passthrough.
// This allows any registry operation to be used without a native binary encoding.
func (c *BinaryClient) SendJSON(msg map[string]interface{}) (map[string]interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closedLocked() {
		return nil, ErrClosed
	}

	resp, err := c.sendJSONLocked(msg)
	if err != nil && resp == nil && !c.closedLocked() {
		if reconnErr := c.reconnect(err); reconnErr != nil {
			return nil, binaryReconnectFailed("send", err, reconnErr)
		}
		resp, err = c.sendJSONLocked(msg)
	}
	return resp, err
}

func (c *BinaryClient) sendJSONLocked(msg map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("json encode: %w", err)
	}
	if c.conn == nil {
		return nil, errNotConnected
	}

	if err := wire.WriteFrame(c.conn, wire.MsgJSON, body); err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	msgType, payload, readErr := wire.ReadFrame(c.conn)
	c.conn.SetReadDeadline(time.Time{})
	if readErr != nil {
		return nil, fmt.Errorf("recv: %w", readErr)
	}

	if msgType == wire.MsgError {
		errMsg := wire.DecodeError(payload)
		return map[string]interface{}{"type": "error", "error": errMsg}, fmt.Errorf("registry: %s", errMsg)
	}
	if msgType != wire.MsgJSON {
		return nil, fmt.Errorf("unexpected response type 0x%02x for JSON passthrough", msgType)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, fmt.Errorf("json decode response: %w", err)
	}
	if errVal, ok := resp["error"]; ok {
		return resp, fmt.Errorf("registry: %v", errVal)
	}
	// PILOT-132: reject valid JSON that lacks the expected "type" envelope key.
	if _, hasType := resp["type"]; !hasType && len(resp) > 0 {
		return resp, fmt.Errorf("registry: malformed response (missing %q field)", "type")
	}
	return resp, nil
}
