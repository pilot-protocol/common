// SPDX-License-Identifier: AGPL-3.0-or-later

package driver

import (
	"errors"
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

// shortConfirmTimeout makes SendToConfirmed time out after timeout, for the
// duration of the test.
func shortConfirmTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	ot := sendToConfirmTimeout
	sendToConfirmTimeout = timeout
	t.Cleanup(func() { sendToConfirmTimeout = ot })
}

// A confirmed send that times out is answered by the daemon later; that
// answer must not become the next confirmed send's. In review, a second send
// that the daemon rejected came back confirmed=true because it received the
// first send's late OK.
func TestSendToConfirmedLateOKIsNotTheNextSendsAnswer(t *testing.T) {
	shortConfirmTimeout(t, 200*time.Millisecond)
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

	if ok, err := drv.SendToConfirmed(dst, 5000, []byte("first")); ok || !errors.Is(err, ErrConfirmTimeout) {
		t.Fatalf("first send = (%v, %v), want ErrConfirmTimeout", ok, err)
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
	shortConfirmTimeout(t, 100*time.Millisecond)
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
// never taken as a confirmed send's answer.
func TestSendToConfirmedNeverTakesAnotherRequestsAnswer(t *testing.T) {
	shortConfirmTimeout(t, 2*time.Second)
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
	shortConfirmTimeout(t, 200*time.Millisecond)
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
	shortConfirmTimeout(t, 300*time.Millisecond)
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

// A confirmed send's late answer never reaches another kind of request, and
// waiting for it does not hold other requests up: an Info sent while the
// answer is still owed gets its own reply, even when the late answer is an
// error frame arriving just before it.
func TestSendToConfirmedLateAnswerDoesNotReachOrHoldOtherRequests(t *testing.T) {
	shortConfirmTimeout(t, 100*time.Millisecond)
	d := newFakeDaemon(t)
	defer d.close()
	answered := false
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		if !answered {
			return nil // answered late, below
		}
		return [][]byte{{cmdSendToOK}}
	})
	infoOK := append([]byte{cmdInfoOK}, `{"node_id":7}`...)
	d.onCmd(cmdInfo, func(frame []byte) [][]byte {
		return [][]byte{infoOK}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	if _, err := drv.SendToConfirmed(dst, 5000, []byte("x")); !errors.Is(err, ErrConfirmTimeout) {
		t.Fatalf("confirmed send = %v, want ErrConfirmTimeout", err)
	}
	// The answer is still owed. An Info is not held up by it...
	start := time.Now()
	if _, err := drv.Info(); err != nil {
		t.Fatalf("Info while a confirmed send's answer is owed: %v", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("Info waited %s behind an unanswered confirmed send", waited)
	}
	// ...and the late error, arriving just before an Info's reply, is not
	// taken as that reply.
	d.onCmd(cmdInfo, func(frame []byte) [][]byte {
		answered = true
		return [][]byte{ipcErrorFrame("sendto: resolve node 7: not found"), infoOK}
	})
	info, err := drv.Info()
	if err != nil {
		t.Fatalf("Info took the confirmed send's late error as its reply: %v", err)
	}
	if info["node_id"] != float64(7) {
		t.Errorf("Info = %v", info)
	}
	// The late answer has gone by, so the next confirmed send gets its own.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok, err := drv.SendToConfirmed(dst, 5000, []byte("y"))
		if errors.Is(err, ErrConfirmQueueTimeout) && time.Now().Before(deadline) {
			continue
		}
		if err != nil || !ok {
			t.Fatalf("send after the late answer = (%v, %v), want (true, nil)", ok, err)
		}
		break
	}
}

// The next confirmed send waits for a late answer however late it is: while
// it is owed, the next send gets ErrConfirmQueueTimeout and nothing is
// written; once it arrives, the next send gets its own answer. In review, a
// time limit on that wait let a very late OK become the next send's answer.
func TestSendToConfirmedWaitsOutAVeryLateAnswer(t *testing.T) {
	shortConfirmTimeout(t, 100*time.Millisecond)
	d := newFakeDaemon(t)
	defer d.close()
	calls := 0
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte {
		calls++
		if calls == 1 {
			return nil // answered late, below
		}
		return [][]byte{ipcErrorFrame("sendto: port 5000 not allowed by network 0 policy")}
	})
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer drv.Close()
	dst := protocol.Addr{Network: 0, Node: 7}

	if _, err := drv.SendToConfirmed(dst, 5000, []byte("first")); !errors.Is(err, ErrConfirmTimeout) {
		t.Fatalf("first send = %v, want ErrConfirmTimeout", err)
	}
	for i := 0; i < 3; i++ {
		if ok, err := drv.SendToConfirmed(dst, 5000, []byte("waits")); ok || !errors.Is(err, ErrConfirmQueueTimeout) {
			t.Fatalf("send while the first answer is owed = (%v, %v), want ErrConfirmQueueTimeout", ok, err)
		}
	}
	if n := framesOf(d, cmdSendToConfirm); n != 1 {
		t.Fatalf("%d confirmed sends written while an answer was owed, want only the first", n)
	}
	d.push([]byte{cmdSendToOK}) // the first send's very late OK
	deadline := time.Now().Add(2 * time.Second)
	for {
		ok, err := drv.SendToConfirmed(dst, 5000, []byte("second"))
		if errors.Is(err, ErrConfirmQueueTimeout) && time.Now().Before(deadline) {
			continue // the late OK is still on its way
		}
		if ok || err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("send after the late OK = (%v, %v), want its own rejection", ok, err)
		}
		break
	}
}

// Closing the Driver while a late answer is owed releases the waiter: later
// calls fail at once instead of queueing.
func TestSendToConfirmedCloseWhileAnAnswerIsOwed(t *testing.T) {
	shortConfirmTimeout(t, 100*time.Millisecond)
	d := newFakeDaemon(t)
	defer d.close()
	d.onCmd(cmdSendToConfirm, func(frame []byte) [][]byte { return nil })
	drv, err := Connect(d.path)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	dst := protocol.Addr{Network: 0, Node: 7}
	if _, err := drv.SendToConfirmed(dst, 5000, []byte("x")); !errors.Is(err, ErrConfirmTimeout) {
		t.Fatalf("send = %v, want ErrConfirmTimeout", err)
	}
	drv.Close()
	start := time.Now()
	if _, err := drv.SendToConfirmed(dst, 5000, []byte("x")); err == nil || errors.Is(err, ErrConfirmQueueTimeout) {
		t.Fatalf("send after Close = %v, want a disconnect error", err)
	}
	if waited := time.Since(start); waited > 50*time.Millisecond {
		t.Errorf("send after Close took %s", waited)
	}
}
