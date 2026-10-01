// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

func ipcErrorFrame(msg string) []byte {
	return append([]byte{cmdError, 0, 1}, msg...)
}

func framesOf(d *fakeDaemon, cmd byte) int {
	n := 0
	for _, f := range d.allFrames() {
		if f[0] == cmd {
			n++
		}
	}
	return n
}

// TestSendToConfirmedReportsDaemonOutcome: against a daemon that supports
// cmdSendToConfirm, the daemon's OK and its error both reach the caller.
func TestSendToConfirmedReportsDaemonOutcome(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	fail := false
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		if fail {
			return [][]byte{ipcErrorFrame("sendto: ephemeral ports exhausted")}
		}
		return [][]byte{{cmdSendToOK}}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	confirmed, err := drv.SendToConfirmed(dst, 5000, []byte("hi"))
	if err != nil || !confirmed {
		t.Fatalf("SendToConfirmed = (%v, %v), want (true, nil)", confirmed, err)
	}
	want := make([]byte, 1+protocol.AddrSize+2)
	want[0] = cmdSendToConfirm
	dst.MarshalTo(want, 1)
	want[1+protocol.AddrSize], want[2+protocol.AddrSize] = 0x13, 0x88
	if got := d.lastFrame(); string(got) != string(want)+"hi" {
		t.Fatalf("frame = %x, want %x", got, string(want)+"hi")
	}

	d.mu.Lock()
	fail = true
	d.mu.Unlock()
	confirmed, err = drv.SendToConfirmed(dst, 5000, []byte("hi"))
	if confirmed || err == nil || !strings.Contains(err.Error(), "ephemeral ports exhausted") {
		t.Fatalf("SendToConfirmed = (%v, %v), want the daemon's error", confirmed, err)
	}
	if n := framesOf(d, cmdSendTo); n != 0 {
		t.Fatalf("%d legacy cmdSendTo frames sent to a daemon that supports confirmed sends", n)
	}

	if _, err := drv.SendToConfirmed(protocol.BroadcastAddr(1), 5000, []byte("hi")); err == nil {
		t.Fatal("broadcast destination accepted")
	}
}

// TestSendToConfirmedFallsBackOnOlderDaemon: a daemon without the command
// answers "unknown command". The driver then sends the datagram with the
// legacy fire-and-forget command, reports it as unconfirmed, and does not
// probe again.
func TestSendToConfirmedFallsBackOnOlderDaemon(t *testing.T) {
	t.Parallel()
	d := newFakeDaemon(t)
	defer d.close()

	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		return [][]byte{ipcErrorFrame(fmt.Sprintf("unknown command: 0x%02X", frame[0]))}
	})
	d.onCmd(cmdInfo, func(frame []byte) [][]byte {
		return [][]byte{append([]byte{cmdInfoOK}, "{}"...)}
	})

	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	for i := 0; i < 3; i++ {
		confirmed, err := drv.SendToConfirmed(dst, 5000, []byte("hi"))
		if err != nil || confirmed {
			t.Fatalf("call %d: SendToConfirmed = (%v, %v), want (false, nil)", i, confirmed, err)
		}
	}
	// A request/reply round trip puts the fire-and-forget frames behind us.
	if _, err := drv.Info(); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if n := framesOf(d, cmdSendToConfirm); n != 1 {
		t.Errorf("daemon was probed %d times, want 1", n)
	}
	if n := framesOf(d, cmdSendTo); n != 3 {
		t.Errorf("%d legacy datagrams sent, want 3", n)
	}
}
