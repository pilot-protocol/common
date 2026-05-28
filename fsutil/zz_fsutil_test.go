// SPDX-License-Identifier: AGPL-3.0-or-later

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendSync_CreatesAndAppends(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "wal.log")

	if err := AppendSync(path, []byte("first\n")); err != nil {
		t.Fatalf("first AppendSync: %v", err)
	}
	if err := AppendSync(path, []byte("second\n")); err != nil {
		t.Fatalf("second AppendSync: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(body) != "first\nsecond\n" {
		t.Errorf("got %q, want 'first\\nsecond\\n'", body)
	}
}

func TestAppendSync_OpenError(t *testing.T) {
	t.Parallel()
	// Write under a non-existent parent dir → open fails.
	if err := AppendSync("/no/such/parent/file.txt", []byte("x")); err == nil {
		t.Error("expected error on bad path")
	}
}

func TestAtomicWrite_HappyPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	if err := AtomicWrite(path, []byte("hello")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "hello" {
		t.Errorf("got %q", body)
	}
	// tmp file must be cleaned up by rename.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf(".tmp file should be gone: %v", err)
	}
}

func TestAtomicWrite_OverwritesExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := AtomicWrite(path, []byte("new")); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "new" {
		t.Errorf("got %q, want 'new'", body)
	}
}

func TestAtomicWrite_OpenError(t *testing.T) {
	t.Parallel()
	if err := AtomicWrite("/no/such/parent/dir/file.txt", []byte("x")); err == nil {
		t.Error("expected error opening tmp under bad path")
	}
}
