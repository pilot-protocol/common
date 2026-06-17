// SPDX-License-Identifier: AGPL-3.0-or-later

// Package consent provides opt-out consent flags stored in ~/.pilot/config.json.
//
// Three flags are recognised: "telemetry", "broadcasts", and "reviews".
// All flags default to true (opt-out model) when absent from the config file or
// when the config file does not exist yet.
//
// The config file format is:
//
//	{"consent": {"telemetry": true, "broadcasts": true, "reviews": false}}
//
// Writes are atomic: the package reads the existing file, updates only the
// "consent" subkey, and writes back via a temp-file + rename so the file is
// never left in a partial state on crash.
package consent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pilot-protocol/common/fsutil"
)

// validFlags is the set of flag names the package recognises.
var validFlags = map[string]struct{}{
	"telemetry":  {},
	"broadcasts": {},
	"reviews":    {},
}

// configPath returns the path to ~/.pilot/config.json given the user's home
// directory. Callers pass home so the function is testable without touching
// the real home directory.
func configPath(home string) string {
	return filepath.Join(home, ".pilot", "config.json")
}

// readRaw reads and JSON-decodes ~/.pilot/config.json into a generic map.
// If the file does not exist an empty (non-nil) map is returned so callers
// can treat absent-file the same as empty-file.
func readRaw(home string) (map[string]interface{}, error) {
	path := configPath(home)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("consent: read config: %w", err)
	}
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("consent: parse config: %w", err)
	}
	return root, nil
}

// consentMap extracts the "consent" submap from root, returning an empty
// (non-nil) map when the subkey is absent or has the wrong type.
func consentMap(root map[string]interface{}) map[string]interface{} {
	if v, ok := root["consent"]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return map[string]interface{}{}
}

// GetConsent returns the consent value for flag ("telemetry", "broadcasts",
// "reviews"). It defaults to true (opt-out model) when the flag is absent
// from the config file, or when the config file does not exist yet. Unknown
// flag names also return true so that callers which don't validate the flag
// name beforehand are safe — use SetConsent to get an error on invalid names.
func GetConsent(home, flag string) bool {
	root, err := readRaw(home)
	if err != nil {
		// On read/parse error fall back to the safe default.
		return true
	}
	cm := consentMap(root)
	v, ok := cm[flag]
	if !ok {
		return true // absent → default true
	}
	b, ok := v.(bool)
	if !ok {
		return true // malformed entry → default true
	}
	return b
}

// SetConsent persists one consent flag. It reads the existing config,
// updates only the consent subkey for the named flag, and writes back
// atomically. The parent directory (~/.pilot) is created if it does not
// exist yet.
//
// flag must be one of "telemetry", "broadcasts", or "reviews"; any other
// value returns a descriptive error and leaves the config file unchanged.
func SetConsent(home, flag string, value bool) error {
	if _, ok := validFlags[flag]; !ok {
		return fmt.Errorf("consent: unknown flag %q: must be one of telemetry, broadcasts, reviews", flag)
	}

	root, err := readRaw(home)
	if err != nil {
		return err
	}

	// Copy the existing consent map and set the new value.
	cm := consentMap(root)
	updated := make(map[string]interface{}, len(cm)+1)
	for k, v := range cm {
		updated[k] = v
	}
	updated[flag] = value
	root["consent"] = updated

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("consent: marshal config: %w", err)
	}

	path := configPath(home)
	// Ensure ~/.pilot exists before trying to write.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("consent: create config dir: %w", err)
	}

	if err := fsutil.AtomicWrite(path, data); err != nil {
		return fmt.Errorf("consent: write config: %w", err)
	}
	return nil
}
