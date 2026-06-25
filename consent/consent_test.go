// SPDX-License-Identifier: AGPL-3.0-or-later

package consent_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/common/consent"
)

// writeConfig is a test helper that writes raw JSON to ~/.pilot/config.json
// inside a temp home directory.
func writeConfig(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir .pilot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// readConfig is a test helper that reads ~/.pilot/config.json from a temp
// home directory and decodes it into a generic map.
func readConfig(t *testing.T, home string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".pilot", "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	return root
}

// --- GetConsent ---

func TestGetConsent_AbsentFile_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	for _, flag := range []string{"telemetry", "broadcasts", "reviews"} {
		if got := consent.GetConsent(home, flag); !got {
			t.Errorf("GetConsent(%q) = false, want true (absent file → default true)", flag)
		}
	}
}

func TestGetConsent_AbsentKey_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// Config exists but has no "consent" subkey.
	writeConfig(t, home, `{"other":"value"}`)
	for _, flag := range []string{"telemetry", "broadcasts", "reviews"} {
		if got := consent.GetConsent(home, flag); !got {
			t.Errorf("GetConsent(%q) = false, want true (absent key → default true)", flag)
		}
	}
}

func TestGetConsent_AbsentFlagWithinConsentMap_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// Consent object exists but the specific flag is absent.
	writeConfig(t, home, `{"consent":{"telemetry":false}}`)
	if got := consent.GetConsent(home, "broadcasts"); !got {
		t.Error("GetConsent(broadcasts) = false, want true (absent within consent map → default true)")
	}
}

func TestGetConsent_ReadsStoredFalse(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeConfig(t, home, `{"consent":{"telemetry":false,"broadcasts":true,"reviews":false}}`)
	if got := consent.GetConsent(home, "telemetry"); got {
		t.Error("GetConsent(telemetry) = true, want false")
	}
	if got := consent.GetConsent(home, "broadcasts"); !got {
		t.Error("GetConsent(broadcasts) = false, want true")
	}
	if got := consent.GetConsent(home, "reviews"); got {
		t.Error("GetConsent(reviews) = true, want false")
	}
}

func TestGetConsent_MalformedConsentValue_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// The flag value is a string, not a bool.
	writeConfig(t, home, `{"consent":{"telemetry":"yes"}}`)
	if got := consent.GetConsent(home, "telemetry"); !got {
		t.Error("GetConsent(telemetry) = false, want true (malformed value → default true)")
	}
}

func TestGetConsent_MalformedConfigFile_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// Config file exists but contains invalid JSON; readRaw returns a parse
	// error and GetConsent falls back to the safe opt-out default (true).
	writeConfig(t, home, `{not valid json`)
	for _, flag := range []string{"telemetry", "broadcasts", "reviews"} {
		if got := consent.GetConsent(home, flag); !got {
			t.Errorf("GetConsent(%q) = false, want true (unparseable config → default true)", flag)
		}
	}
}

func TestGetConsent_UnknownFlag_DefaultsTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeConfig(t, home, `{"consent":{"telemetry":false}}`)
	// Unknown flag should default to true, not leak the telemetry value.
	if got := consent.GetConsent(home, "unknown-flag"); !got {
		t.Error("GetConsent(unknown-flag) = false, want true (unknown flag → default true)")
	}
}

// --- SetConsent ---

func TestSetConsent_InvalidFlag_ReturnsError(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	err := consent.SetConsent(home, "invalid_flag", true)
	if err == nil {
		t.Fatal("SetConsent(invalid_flag) expected error, got nil")
	}
}

func TestSetConsent_InvalidFlag_DoesNotCreateFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	_ = consent.SetConsent(home, "invalid_flag", true)
	if _, err := os.Stat(filepath.Join(home, ".pilot", "config.json")); !os.IsNotExist(err) {
		t.Error("config.json should not be created for invalid flag")
	}
}

func TestSetConsent_MalformedConfigFile_ReturnsError(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// A pre-existing unparseable config makes readRaw fail; SetConsent
	// propagates the error rather than clobbering the file.
	writeConfig(t, home, `{not valid json`)
	if err := consent.SetConsent(home, "telemetry", false); err == nil {
		t.Fatal("SetConsent on malformed config = nil error, want parse error")
	}
}

func TestSetConsent_CreatesFileAndDir(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// ~/.pilot does not exist yet.
	if err := consent.SetConsent(home, "telemetry", false); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".pilot", "config.json")); err != nil {
		t.Fatalf("config.json not created: %v", err)
	}
}

func TestSetConsent_SetFalseReadBackFalse(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := consent.SetConsent(home, "telemetry", false); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	if got := consent.GetConsent(home, "telemetry"); got {
		t.Error("GetConsent(telemetry) = true, want false after SetConsent(false)")
	}
}

func TestSetConsent_SetFalseThenTrueReadBackTrue(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := consent.SetConsent(home, "reviews", false); err != nil {
		t.Fatalf("SetConsent(false): %v", err)
	}
	if err := consent.SetConsent(home, "reviews", true); err != nil {
		t.Fatalf("SetConsent(true): %v", err)
	}
	if got := consent.GetConsent(home, "reviews"); !got {
		t.Error("GetConsent(reviews) = false, want true after round-trip false→true")
	}
}

func TestSetConsent_OneFlagDoesNotAffectOthers(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// Set telemetry=false; broadcasts and reviews must still return true.
	if err := consent.SetConsent(home, "telemetry", false); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	if got := consent.GetConsent(home, "broadcasts"); !got {
		t.Error("GetConsent(broadcasts) = false, want true (unset flag must default true)")
	}
	if got := consent.GetConsent(home, "reviews"); !got {
		t.Error("GetConsent(reviews) = false, want true (unset flag must default true)")
	}
}

func TestSetConsent_PreservesOtherTopLevelKeys(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	// Pre-populate config with a non-consent key.
	writeConfig(t, home, `{"other_key":"kept","consent":{"broadcasts":false}}`)
	if err := consent.SetConsent(home, "telemetry", false); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	root := readConfig(t, home)
	if root["other_key"] != "kept" {
		t.Errorf("other_key = %v, want 'kept' (SetConsent must not drop unrelated keys)", root["other_key"])
	}
}

func TestSetConsent_PreservesExistingConsentFlags(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	writeConfig(t, home, `{"consent":{"telemetry":false,"broadcasts":false,"reviews":true}}`)
	// Update only broadcasts.
	if err := consent.SetConsent(home, "broadcasts", true); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	root := readConfig(t, home)
	cm := root["consent"].(map[string]interface{})
	if cm["telemetry"] != false {
		t.Errorf("telemetry = %v, want false (must be unchanged)", cm["telemetry"])
	}
	if cm["broadcasts"] != true {
		t.Errorf("broadcasts = %v, want true (just set)", cm["broadcasts"])
	}
	if cm["reviews"] != true {
		t.Errorf("reviews = %v, want true (must be unchanged)", cm["reviews"])
	}
}

func TestSetConsent_AtomicWrite_NoTmpFile(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := consent.SetConsent(home, "telemetry", false); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	// After a successful write the .tmp file must be gone (renamed away).
	tmpPath := filepath.Join(home, ".pilot", "config.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("config.json.tmp should not exist after successful SetConsent")
	}
}

func TestSetConsent_AllThreeFlagsIndependently(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	flags := []string{"telemetry", "broadcasts", "reviews"}
	// Set all to false one by one; verify each after each write.
	for _, flag := range flags {
		if err := consent.SetConsent(home, flag, false); err != nil {
			t.Fatalf("SetConsent(%s, false): %v", flag, err)
		}
		if got := consent.GetConsent(home, flag); got {
			t.Errorf("GetConsent(%s) = true after SetConsent(false)", flag)
		}
	}
	// Now set all back to true.
	for _, flag := range flags {
		if err := consent.SetConsent(home, flag, true); err != nil {
			t.Fatalf("SetConsent(%s, true): %v", flag, err)
		}
		if got := consent.GetConsent(home, flag); !got {
			t.Errorf("GetConsent(%s) = false after SetConsent(true)", flag)
		}
	}
}

func TestSetConsent_InvalidFlagErrorMessage(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	err := consent.SetConsent(home, "badname", false)
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	msg := err.Error()
	for _, want := range []string{"badname", "telemetry", "broadcasts", "reviews"} {
		found := false
		for i := 0; i+len(want) <= len(msg); i++ {
			if msg[i:i+len(want)] == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("error message %q missing word %q", msg, want)
		}
	}
}
