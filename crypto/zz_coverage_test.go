// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestLoadIdentity_LoosePermissionsError checks that LoadIdentity
// refuses to load an identity file with group/other-readable permissions.
func TestLoadIdentity_LoosePermissionsError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions only")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// Loosen permissions so the error branch trips.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, err = LoadIdentity(path)
	if err == nil {
		t.Fatal("expected error for loose permissions (0o644)")
	}
	if !strings.Contains(err.Error(), "loose permissions") {
		t.Fatalf("error %q missing 'loose permissions'", err)
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error %q missing 'chmod 600' instruction", err)
	}
}

// TestLoadIdentity_ReadFileNonNotExistError covers the os.ReadFile
// error branch where the error is *not* IsNotExist. We create a
// directory with strict 0o700 perms (passes the permissions gate),
// then os.ReadFile on the directory fails with EISDIR.
func TestLoadIdentity_ReadFileNonNotExistError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("EISDIR is unix-specific")
	}
	dir := t.TempDir()
	// Create a subdirectory with strict perms that passes the gate.
	subdir := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, err := LoadIdentity(subdir)
	if err == nil {
		t.Fatal("expected read error against a directory path")
	}
	if !strings.Contains(err.Error(), "read identity") {
		t.Fatalf("error %q missing 'read identity' wrap", err)
	}
}

// TestLoadIdentity_PermsExactly600OK confirms that a strict 0o600 file
// loads successfully (passes the permissions gate).
func TestLoadIdentity_PermsExactly600OK(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix file permissions only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	id, _ := GenerateIdentity()
	if err := SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// SaveIdentity already writes 0o600 but be explicit.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if _, err := LoadIdentity(path); err != nil {
		t.Fatalf("LoadIdentity with 0o600 should succeed: %v", err)
	}
}

// TestSignVerify_EmptyMessage edge: ed25519 over zero-length input is
// well-defined; ensure our wrappers don't choke.
func TestSignVerify_EmptyMessage(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	sig := id.Sign(nil)
	if !Verify(id.PublicKey, nil, sig) {
		t.Fatal("Verify rejected signature over empty message")
	}
	if !Verify(id.PublicKey, []byte{}, sig) {
		t.Fatal("Verify rejected signature over []byte{} (same as nil)")
	}
}

// TestSignVerify_LargeMessage exercises the path with a sizeable payload
// (1 MiB) to make sure neither Sign nor Verify imposes a hidden cap.
func TestSignVerify_LargeMessage(t *testing.T) {
	t.Parallel()
	id, _ := GenerateIdentity()
	msg := bytes.Repeat([]byte("A"), 1<<20)
	sig := id.Sign(msg)
	if !Verify(id.PublicKey, msg, sig) {
		t.Fatal("Verify rejected large-message signature")
	}
}

// TestEncodeDecodePublicKey_EmptyString hits the base64-of-empty case:
// base64 decodes to an empty []byte, which fails the size check.
func TestEncodeDecodePublicKey_EmptyString(t *testing.T) {
	t.Parallel()
	_, err := DecodePublicKey("")
	if err == nil {
		t.Fatal("expected size error on empty string")
	}
	if !strings.Contains(err.Error(), "invalid public key size") {
		t.Fatalf("error %q missing size-error wrap", err)
	}
}

func TestEncodeDecodePrivateKey_EmptyString(t *testing.T) {
	t.Parallel()
	_, err := DecodePrivateKey("")
	if err == nil {
		t.Fatal("expected size error on empty string")
	}
	if !strings.Contains(err.Error(), "invalid private key size") {
		t.Fatalf("error %q missing size-error wrap", err)
	}
}

// TestSaveLoad_ConcurrentReaders is a smoke test: many goroutines load
// the same identity file in parallel. SaveIdentity is a one-shot writer;
// LoadIdentity should be safely callable in parallel.
func TestSaveLoad_ConcurrentReaders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	id, _ := GenerateIdentity()
	if err := SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := LoadIdentity(path)
			if err != nil {
				errs <- err
				return
			}
			if !got.PublicKey.Equal(id.PublicKey) {
				errs <- io.ErrUnexpectedEOF // sentinel
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent LoadIdentity: %v", e)
	}
}

// TestSaveLoad_OverwriteExisting ensures SaveIdentity over an existing
// file replaces it with the new keypair (no append, no merge).
func TestSaveLoad_OverwriteExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	if err := SaveIdentity(path, id1); err != nil {
		t.Fatalf("first SaveIdentity: %v", err)
	}
	if err := SaveIdentity(path, id2); err != nil {
		t.Fatalf("overwrite SaveIdentity: %v", err)
	}
	got, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if !got.PublicKey.Equal(id2.PublicKey) {
		t.Fatal("overwrite did not persist the second identity")
	}
	if got.PublicKey.Equal(id1.PublicKey) {
		t.Fatal("overwrite still returned the first identity")
	}
}
