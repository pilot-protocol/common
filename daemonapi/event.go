// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

import "time"

// Event is the payload structure carried over the daemon event bus.
// Mirrors the layout of the concrete event type in web4/pkg/daemon
// so subscriber channels receive identical-shaped values across the
// interface boundary.
type Event struct {
	Topic   string
	NodeID  uint32
	Time    time.Time
	Payload map[string]any
}

// EventBus is the in-process pub/sub surface plugins consume. The
// concrete *inProcessBus in web4/pkg/daemon satisfies this; plugins
// retrieve it via Daemon.Bus() and Subscribe / Publish without
// knowing the underlying implementation.
type EventBus interface {
	// Publish emits the topic + payload to every subscriber whose
	// pattern matches the topic. Non-blocking; events may be dropped
	// on per-subscriber backpressure.
	Publish(topic string, payload map[string]any)

	// Subscribe registers a pattern-matching subscriber and returns
	// the receive channel plus a cancellation closure. Calling the
	// closure stops delivery and drains the buffer.
	Subscribe(pattern string) (<-chan Event, func())
}
