// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

// shortConfirmTimeouts makes SendToConfirmed time out after timeout and let
// other requests through drain after that, for the duration of the test.
func shortConfirmTimeouts(t *testing.T, timeout, drain time.Duration) {
	t.Helper()
	ot, od := sendToConfirmTimeout, sendToConfirmDrain
	sendToConfirmTimeout, sendToConfirmDrain = timeout, drain
	t.Cleanup(func() { sendToConfirmTimeout, sendToConfirmDrain = ot, od })
}

// A confirmed send that times out is answered by the daemon later; that
// answer must not become the next confirmed send's. In review, a second send
// that the daemon rejected came back confirmed=true because it received the
// first send's late OK.
func TestSendToConfirmedLateOKIsNotTheNextSendsAnswer(t *testing.T) {
	shortConfirmTimeouts(t, 200*time.Millisecond, 5*time.Second)
	d := newFakeDaemon(t)
	defer d.close()
	calls := 0
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		calls++
		if calls == 1 {
			time.Sleep(300 * time.Millisecond) // answered in order, like the daemon
			return [][]byte{{cmdSendToOK}}
		}
		return [][]byte{ipcErrorFrame("sendto: port 5000 not allowed by network 0 policy")}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	if ok, err := drv.SendToConfirmed(dst, 5000, []byte("first")); ok || err == nil || !strings.Contains(err.Error(), "may or may not") {
		t.Fatalf("first send = (%v, %v), want a timeout saying the outcome is unknown", ok, err)
	}
	ok, err := drv.SendToConfirmed(dst, 5000, []byte("second"))
	if ok || err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("second send = (%v, %v), want its own rejection", ok, err)
	}
}

// A late answer that is an error, arriving while nothing is waiting, used to
// leave the Driver convinced an answer was still owed, after which every
// confirmed send timed out. The next send must get its own answer.
func TestSendToConfirmedLateErrorWhileIdleDoesNotWedgeTheDriver(t *testing.T) {
	shortConfirmTimeouts(t, 100*time.Millisecond, 5*time.Second)
	d := newFakeDaemon(t)
	defer d.close()
	calls := 0
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		calls++
		if calls == 1 {
			time.Sleep(250 * time.Millisecond)
			return [][]byte{ipcErrorFrame("sendto: resolve node 7: not found")}
		}
		return [][]byte{{cmdSendToOK}}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	if ok, _ := drv.SendToConfirmed(dst, 5000, []byte("first")); ok {
		t.Fatal("first send should time out")
	}
	time.Sleep(300 * time.Millisecond) // the late error arrives with nothing waiting
	for i := 0; i < 3; i++ {
		if ok, err := drv.SendToConfirmed(dst, 5000, []byte("next")); err != nil || !ok {
			t.Fatalf("send %d after the late error = (%v, %v), want (true, nil)", i+2, ok, err)
		}
	}
}

// A late error from a different request (here an Info that timed out) is
// never taken as a confirmed send's answer, and a confirmed send's late
// answer never reaches another request.
func TestSendToConfirmedNeverTakesAnotherRequestsAnswer(t *testing.T) {
	shortConfirmTimeouts(t, 2*time.Second, 5*time.Second)
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdInfo, func(frame []byte) [][]byte {
		time.Sleep(300 * time.Millisecond)
		return [][]byte{ipcErrorFrame("info: registry unreachable")}
	})
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		return [][]byte{ipcErrorFrame("sendto: port 5000 not allowed by network 0 policy")}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	// The Info request is abandoned before its error arrives.
	if _, err := drv.ipc.sendAndWaitTimeout([]byte{cmdInfo}, cmdInfoOK, 100*time.Millisecond); err == nil {
		t.Fatal("info should time out")
	}
	ok, err := drv.SendToConfirmed(protocol.Addr{Network: 0, Node: 7}, 5000, []byte("x"))
	if ok || err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("confirmed send = (%v, %v), want its own rejection, not the Info's late error", ok, err)
	}
}

// Against a daemon that predates confirmed sends, a first probe that times
// out must not stop the fallback: the next call still learns the daemon is
// old and sends the datagram the legacy way.
func TestSendToConfirmedFallsBackAfterALegacyProbeTimedOut(t *testing.T) {
	shortConfirmTimeouts(t, 200*time.Millisecond, 5*time.Second)
	d := newFakeDaemon(t)
	defer d.close()
	calls := 0
	unknown := fmt.Sprintf("unknown command: 0x%02X", cmdSendToConfirm)
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		calls++
		if calls == 1 {
			time.Sleep(250 * time.Millisecond)
		}
		return [][]byte{ipcErrorFrame(unknown)}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	if ok, _ := drv.SendToConfirmed(dst, 5000, []byte("first")); ok {
		t.Fatal("first probe should time out")
	}
	// The second call waits for the first's late answer (50ms on) and then
	// gets its own.
	ok, err := drv.SendToConfirmed(dst, 5000, []byte("second"))
	if ok || err != nil {
		t.Fatalf("second send = (%v, %v), want (false, nil) via the legacy fallback", ok, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for framesOf(d, cmdSendTo) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if framesOf(d, cmdSendTo) == 0 {
		t.Fatal("the fallback sent no legacy datagram")
	}
}

// Time spent queued behind another request does not count against the wait
// for the daemon's answer.
func TestSendToConfirmedReplyWaitStartsWhenTheRequestIsWritten(t *testing.T) {
	shortConfirmTimeouts(t, 300*time.Millisecond, 5*time.Second)
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdInfo, func(frame []byte) [][]byte {
		time.Sleep(250 * time.Millisecond)
		return [][]byte{append([]byte{cmdInfoOK}, []byte("{}")...)}
	})
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		time.Sleep(150 * time.Millisecond)
		return [][]byte{{cmdSendToOK}}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()

	infoDone := make(chan struct{})
	go func() {
		defer close(infoDone)
		_, _ = drv.ipc.sendAndWaitTimeout([]byte{cmdInfo}, cmdInfoOK, 5*time.Second)
	}()
	time.Sleep(20 * time.Millisecond) // the Info holds the lane for ~250ms
	ok, err := drv.SendToConfirmed(protocol.Addr{Network: 0, Node: 7}, 5000, []byte("x"))
	<-infoDone
	if err != nil || !ok {
		t.Fatalf("confirmed send queued ~230ms behind an Info and answered 150ms after its write = (%v, %v), want (true, nil)", ok, err)
	}
}
