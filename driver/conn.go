// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
	"github.com/pilot-protocol/common/protocol"
)

// maxSendChunk is the largest payload we will pack into one cmdSend IPC
// message. IPC messages are capped at ipcutil.MaxMessageSize; we reserve
// 5 bytes for the cmdSend+conn_id header and leave a small safety margin.
const maxSendChunk = ipcutil.MaxMessageSize - 64

// Conn implements net.Conn over a Pilot Protocol stream.
//
// Concurrency: like *net.TCPConn, a Conn may be used by at most one reader
// and one writer goroutine at a time. Read serialises concurrent callers
// with readMu (so recvBuf is never corrupted), but interleaving two
// readers still yields each a non-deterministic slice of the stream; do
// not do that. Write is safe for one writer; concurrent writers may
// interleave chunks on the wire. SetDeadline/SetReadDeadline/
// SetWriteDeadline are safe to call from any goroutine.
type Conn struct {
	id         uint32
	localAddr  protocol.SocketAddr
	remoteAddr protocol.SocketAddr
	ipc        *ipcClient
	recvCh     chan []byte

	// readMu serialises Read so recvBuf (leftover from a previous read)
	// cannot be observed or mutated by two readers at once.
	readMu  sync.Mutex
	recvBuf []byte // leftover from previous read; guarded by readMu

	mu            sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCh    chan struct{} // closed when deadline is set/changed
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Drain leftover first
	if len(c.recvBuf) > 0 {
		n := copy(b, c.recvBuf)
		c.recvBuf = c.recvBuf[n:]
		return n, nil
	}

	c.mu.Lock()
	dl := c.readDeadline
	dch := c.deadlineCh
	c.mu.Unlock()

	// Check if deadline already passed
	if !dl.IsZero() && !time.Now().Before(dl) {
		return 0, os.ErrDeadlineExceeded
	}

	// Set up timer if deadline is set
	var timer <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}

	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			c.recvBuf = data[n:]
		}
		return n, nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-dch:
		// Deadline was changed, re-check
		return 0, os.ErrDeadlineExceeded
	}
}

// Write enqueues b to the local daemon over IPC, splitting it into
// maxSendChunk-sized cmdSend frames.
//
// Send semantics: a nil error and n == len(b) mean every chunk was handed
// to the local daemon over IPC — NOT that the bytes were transmitted on the
// wire or acknowledged by the peer. The Pilot stream layer in the daemon
// handles retransmission/ordering after this point; Write does not block on
// it. Errors reported here are local IPC write failures or a passed
// write deadline.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, protocol.ErrConnClosed
	}
	wdl := c.writeDeadline
	c.mu.Unlock()

	if !wdl.IsZero() && !time.Now().Before(wdl) {
		return 0, os.ErrDeadlineExceeded
	}

	total := len(b)
	written := 0
	for written < total {
		// Honour the write deadline between chunks so a large, slow write
		// to a backed-up IPC socket cannot block past the deadline.
		if !wdl.IsZero() && !time.Now().Before(wdl) {
			return written, os.ErrDeadlineExceeded
		}
		chunk := total - written
		if chunk > maxSendChunk {
			chunk = maxSendChunk
		}
		msg := make([]byte, 1+4+chunk)
		msg[0] = cmdSend
		binary.BigEndian.PutUint32(msg[1:5], c.id)
		copy(msg[5:], b[written:written+chunk])
		if err := c.ipc.send(msg); err != nil {
			return written, err
		}
		written += chunk
	}
	return written, nil
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.ipc.unregisterRecvCh(c.id)

	msg := make([]byte, 5)
	msg[0] = cmdClose
	binary.BigEndian.PutUint32(msg[1:5], c.id)
	return c.ipc.send(msg)
}

func (c *Conn) LocalAddr() net.Addr  { return pilotAddr(c.localAddr) }
func (c *Conn) RemoteAddr() net.Addr { return pilotAddr(c.remoteAddr) }

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	// Signal any blocked Read to re-check.
	if c.deadlineCh != nil {
		close(c.deadlineCh)
	}
	c.deadlineCh = make(chan struct{})
	c.mu.Unlock()
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	// Signal any blocked Read to re-check
	if c.deadlineCh != nil {
		close(c.deadlineCh)
	}
	c.deadlineCh = make(chan struct{})
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline sets a deadline for Write. A passed deadline causes Write
// to return os.ErrDeadlineExceeded. Because Write never blocks waiting on a
// remote peer (it only enqueues chunks to the local daemon over IPC), the
// deadline is enforced before each chunk rather than via an interrupt — a
// zero time clears it. This satisfies the net.Conn contract instead of the
// previous silent no-op.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// pilotAddr wraps SocketAddr to satisfy net.Addr.
type pilotAddr protocol.SocketAddr

func (a pilotAddr) Network() string { return "pilot" }
func (a pilotAddr) String() string  { return protocol.SocketAddr(a).String() }
