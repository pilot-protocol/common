// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestLoadIdentity_LoosePermissionsWarn covers the slog.Warn branch in
// LoadIdentity that fires when the on-disk file is group/other-readable.
//
// We swap the default slog handler for one that writes to a buffer so we
// can assert the warning was emitted, then restore it.
func TestLoadIdentity_LoosePermissionsWarn(t *testing.T) {
	// NOTE: not t.Parallel() — we mutate the global slog default logger
	// and need to restore it cleanly.
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
	// Loosen permissions so the warn branch trips.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	var buf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(origLogger) })

	loaded, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadIdentity returned nil")
	}
	if !strings.Contains(buf.String(), "loose permissions") {
		t.Fatalf("expected 'loose permissions' warning, got log: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Fatalf("expected WARN level, got log: %q", buf.String())
	}
}

// TestLoadIdentity_ReadFileNonNotExistError covers the os.ReadFile
// error branch where the error is *not* IsNotExist. Pointing the path
// at a directory triggers EISDIR from read(2), which os.IsNotExist
// returns false for, so the wrapped "read identity" path is exercised.
func TestLoadIdentity_ReadFileNonNotExistError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("EISDIR is unix-specific")
	}
	dir := t.TempDir()
	// `dir` itself is a directory; os.Stat succeeds, os.ReadFile fails
	// with a non-NotExist error. The mode bits on a directory include
	// the executable bit for group/other (0o755 typical for TempDir),
	// which is harmless for this test — slog default discards.
	_, err := LoadIdentity(dir)
	if err == nil {
		t.Fatal("expected read error against a directory path")
	}
	if !strings.Contains(err.Error(), "read identity") {
		t.Fatalf("error %q missing 'read identity' wrap", err)
	}
}

// TestLoadIdentity_PermsExactly600NoWarn confirms the *negative* case:
// a strict 0o600 file does NOT trip the warn branch.
func TestLoadIdentity_PermsExactly600NoWarn(t *testing.T) {
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

	var buf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(origLogger) })

	if _, err := LoadIdentity(path); err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if strings.Contains(buf.String(), "loose permissions") {
		t.Fatalf("did not expect warn for 0o600, got log: %q", buf.String())
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
