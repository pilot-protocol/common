// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package netproxy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ownProcessGroup makes cmd the leader of a new process group and has its
// context's cancellation SIGKILL that whole group rather than only cmd, so
// that nothing the command started (a pipeline, a nested shell, a
// background job) outlives a timed-out run.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
}

// killProcessGroup SIGKILLs the process group cmd leads. It reports
// os.ErrProcessDone when the group has no members left.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
