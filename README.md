# common

Pilot Protocol shared helpers. Small, pure-stdlib utilities used by
the protocol repo and the extracted plugin repos. Anything with
non-trivial scope or external dependencies belongs in its own repo,
not here.

## Subpackages

| Path | What it does |
|---|---|
| `fsutil` | `AtomicWrite(path, data)`, `AppendSync(path, data)` — durable file writes. |
| `crypto` | `Identity` — Ed25519 keypair + node-ID derivation, signing/verification. |

## Import paths

```go
import (
    "github.com/pilot-protocol/common/fsutil"
    "github.com/pilot-protocol/common/crypto"
)

if err := fsutil.AtomicWrite(path, blob); err != nil { /* ... */ }
id, err := crypto.NewIdentity()
```

## What goes here vs. its own repo

In: small, single-file helpers with no third-party deps that are used
by ≥2 separate repos in the org.

Out: anything with its own external dependencies (HTTP clients, DB
drivers, etc.), or anything with a meaningful API surface that deserves
independent versioning.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); consumers pull it in via
`require github.com/pilot-protocol/common v0.1.0`. During
co-development consumers use `replace ../common`.
