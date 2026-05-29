// SPDX-License-Identifier: AGPL-3.0-or-later

package daemonapi

// VersionInfo describes a daemon's currently-running version and build
// metadata. Plugins call Daemon.VersionInfo() to discover what they're
// hosted by, useful for compatibility checks before issuing version-
// sensitive RPCs.
type VersionInfo struct {
	// Version is the semver of the running daemon, e.g. "v1.10.5".
	Version string
	// Commit is the git SHA the daemon was built from. Empty in dev builds.
	Commit string
	// BuildTime is the UTC timestamp the daemon binary was assembled.
	BuildTime string
}
