// SPDX-License-Identifier: AGPL-3.0-or-later

package ipcutil

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxMessageSize is the maximum IPC message size (1MB).
const MaxMessageSize = 1 << 20

// Read reads a length-prefixed IPC message from r.
func Read(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxMessageSize {
		return nil, fmt.Errorf("ipc message too large: %d bytes (max %d)", length, MaxMessageSize)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Write writes a length-prefixed IPC message to w as a single Write
// call so the length prefix and payload land atomically on the
// underlying writer. Callers that share the same writer across
// goroutines MUST serialize their own Write calls — this function
// guarantees length+payload framing but does not lock against other
// goroutines writing to the same w.
//
// PILOT-287 originally tried to enforce caller-side safety with a
// global sync.Mutex. That serialized every Write across the entire
// process — including writes on unrelated connections — which on
// Linux (small pipe buffers) deadlocks the moment any single conn's
// writer blocks waiting for its reader: every other Write queued on
// the global mutex stalls behind it, and every reader times out.
// macOS happened to mask the bug behind larger pipe buffers.
//
// Build the frame in one buffer and hand it to w.Write in one call.
// At the syscall level this is atomic for small writes (<=PIPE_BUF on
// Linux, similar elsewhere) — which covers every IPC message the
// daemon sends. For genuine shared-writer concurrency at the higher
// layer, wrap the writer with your own mutex.
func Write(w io.Writer, data []byte) error {
	// Symmetric with Read: a frame the peer would reject on size is
	// refused before allocation rather than written and dropped there.
	if len(data) > MaxMessageSize {
		return fmt.Errorf("ipc message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	_, err := w.Write(frame)
	return err
}
