// SPDX-License-Identifier: AGPL-3.0-or-later

package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveIdentity_HappyAndLoadRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "id.json")

	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if err := SaveIdentity(path, id); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// File created with mode 0600 + parent dir created.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perm = %o, want 0600", perm)
	}

	// Load roundtrips.
	got, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if got == nil {
		t.Fatal("LoadIdentity returned nil")
	}
	if !got.PublicKey.Equal(id.PublicKey) {
		t.Error("PublicKey mismatch after roundtrip")
	}
}

func TestSaveIdentity_MkdirFails(t *testing.T) {
	t.Parallel()
	// /dev/null is a file, not a dir — MkdirAll under it fails.
	err := SaveIdentity("/dev/null/cannot/id.json", &Identity{})
	if err == nil {
		t.Error("expected mkdir error")
	}
}

func TestSaveIdentity_WriteFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Pre-create a directory at the file path → WriteFile fails because
	// it can't open a directory for writing.
	path := filepath.Join(dir, "id.json")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	id, _ := GenerateIdentity()
	if err := SaveIdentity(path, id); err == nil {
		t.Error("expected write error against a directory path")
	}
}

func TestLoadIdentity_MissingFileReturnsNil(t *testing.T) {
	t.Parallel()
	got, err := LoadIdentity("/no/such/path/id.json")
	if err != nil {
		t.Errorf("missing file: err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("missing file: got %v, want nil", got)
	}
}

func TestLoadIdentity_BadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Error("expected JSON parse error")
	}
}

func TestLoadIdentity_BadPrivateKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	if err := os.WriteFile(path, []byte(`{"private_key":"!!!","public_key":"AA=="}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Error("expected decode error")
	}
}

func TestLoadIdentity_PubMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "id.json")
	// Build a valid private key but a public key from a *different* identity.
	id1, _ := GenerateIdentity()
	id2, _ := GenerateIdentity()
	body := `{"private_key":"` + EncodePrivateKey(id1.PrivateKey) + `","public_key":"` + EncodePublicKey(id2.PublicKey) + `"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Error("expected pub-key mismatch error")
	}
}
