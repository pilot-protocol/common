// SPDX-License-Identifier: AGPL-3.0-or-later

package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestAppendSync_EmptyPayload — an empty []byte should still create the
// file (O_CREATE) and not error. f.Write of zero bytes is a no-op.
func TestAppendSync_EmptyPayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.log")
	if err := AppendSync(path, []byte{}); err != nil {
		t.Fatalf("AppendSync(empty): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("size = %d, want 0", info.Size())
	}
	// Mode 0600.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
}

// TestAppendSync_NilPayload — nil should behave identically to empty.
func TestAppendSync_NilPayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.log")
	if err := AppendSync(path, nil); err != nil {
		t.Fatalf("AppendSync(nil): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("size = %d, want 0", info.Size())
	}
}

// TestAppendSync_LargePayload writes a sizeable blob in one shot and
// verifies fsync wrote the whole thing.
func TestAppendSync_LargePayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")
	payload := bytes.Repeat([]byte("Z"), 256<<10) // 256 KiB
	if err := AppendSync(path, payload); err != nil {
		t.Fatalf("AppendSync: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestAppendSync_OpenErrorMessage validates the error wrap, not just
// that an error occurred. Pinning the message protects callers that
// errors.Is / strings.Contains against the wrap.
func TestAppendSync_OpenErrorMessage(t *testing.T) {
	t.Parallel()
	err := AppendSync("/no/such/parent/file.txt", []byte("x"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "open:") {
		t.Fatalf("error %q missing 'open:' wrap", err)
	}
}

// TestAppendSync_ManyAppendsPreserveOrder hammers a single file with
// sequential appends to verify ordering and durability semantics.
// Concurrent appends to the same file are NOT a supported use case
// (POSIX O_APPEND is per-call atomic but ordering is unspecified across
// processes), so we keep this serial.
func TestAppendSync_ManyAppendsPreserveOrder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")
	for i := 0; i < 100; i++ {
		if err := AppendSync(path, []byte("x")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	body, _ := os.ReadFile(path)
	if len(body) != 100 {
		t.Fatalf("len = %d, want 100", len(body))
	}
	if string(body) != strings.Repeat("x", 100) {
		t.Fatalf("content mismatch")
	}
}

// TestAppendSync_OpenAgainstDirectory exercises the open-fails branch
// using a different failure mode (O_WRONLY against a directory).
func TestAppendSync_OpenAgainstDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir() // dir IS a directory; opening it WRONLY fails.
	err := AppendSync(dir, []byte("x"))
	if err == nil {
		t.Fatal("expected open error against a directory")
	}
	if !strings.Contains(err.Error(), "open:") {
		t.Fatalf("error %q missing 'open:' wrap", err)
	}
}

// TestAtomicWrite_RenameFails — pre-create the destination as a
// non-empty directory. The tmp-file open/write/sync/close all succeed
// (sibling path doesn't conflict), but os.Rename(tmp, path) fails
// because you can't rename a file over a non-empty directory.
func TestAtomicWrite_RenameFails(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("rename-onto-dir semantics differ on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}
	// Make the dir non-empty so rename(file → dir) is definitively
	// rejected (an empty dir + rename has differing semantics across
	// kernels: Linux atomically replaces, macOS errors).
	if err := os.WriteFile(filepath.Join(target, "occupant"), []byte("x"), 0o644); err != nil {
		t.Fatalf("setup occupant: %v", err)
	}
	err := AtomicWrite(target, []byte("payload"))
	if err == nil {
		t.Fatal("expected rename error against non-empty directory")
	}
}

// TestAtomicWrite_EmptyPayload — zero-byte writes should still produce
// a zero-byte file.
func TestAtomicWrite_EmptyPayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := AtomicWrite(path, []byte{}); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("size = %d, want 0", info.Size())
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 0600", perm)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp file should be gone: %v", err)
	}
}

// TestAtomicWrite_NilPayload — nil should behave identically to empty.
func TestAtomicWrite_NilPayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.txt")
	if err := AtomicWrite(path, nil); err != nil {
		t.Fatalf("AtomicWrite(nil): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("size = %d, want 0", info.Size())
	}
}

// TestAtomicWrite_LargePayload verifies a big buffer survives the
// open / write / sync / rename / dir-fsync chain intact.
func TestAtomicWrite_LargePayload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	payload := bytes.Repeat([]byte{0xAB, 0xCD}, 256<<10) // 512 KiB
	if err := AtomicWrite(path, payload); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
}

// TestAtomicWrite_PreservesMode0600 — even when overwriting a file
// with permissive 0o644 mode, AtomicWrite's rename should land a 0o600
// inode (because the tmp file is opened 0o600 and rename preserves the
// source inode's perms).
func TestAtomicWrite_PreservesMode0600(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := AtomicWrite(path, []byte("new")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 0600 (atomic write should tighten)", perm)
	}
}

// TestAtomicWrite_ConcurrentWritersToDifferentFiles — separate paths
// should never collide. (Same-path concurrency is racy by design;
// last writer wins, but no torn files.)
func TestAtomicWrite_ConcurrentWritersToDifferentFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var wg sync.WaitGroup
	const n = 16
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			path := filepath.Join(dir, "file-"+strings.Repeat("a", i+1)+".txt")
			payload := []byte(strings.Repeat("p", i+1))
			if err := AtomicWrite(path, payload); err != nil {
				errs <- err
				return
			}
			got, err := os.ReadFile(path)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- &mismatchErr{i: i}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent write: %v", e)
	}
}

type mismatchErr struct{ i int }

func (e *mismatchErr) Error() string { return "payload mismatch" }

// TestAtomicWrite_DirFsyncBestEffort — even when the directory is
// (somehow) unopenable for fsync, AtomicWrite reports success because
// the data is on disk; the directory-entry fsync is best-effort.
// We exercise the happy path here; the failure-mode is unreachable
// from portable Go (you can't make os.Open(filepath.Dir(path)) fail
// after a successful rename in the same dir).
func TestAtomicWrite_DirFsyncBestEffortHappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.txt")
	if err := AtomicWrite(path, []byte("ok")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}
