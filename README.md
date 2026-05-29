# common

[![ci](https://github.com/pilot-protocol/common/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/common/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/common/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/common)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Shared Go helpers for the Pilot Protocol. A small, pure-stdlib library
with subpackages for durable file writes (`fsutil`) and Ed25519 identity
operations (`crypto`).

## Install

```go
import (
    "github.com/pilot-protocol/common/fsutil"
    "github.com/pilot-protocol/common/crypto"
)
```

## Usage

```go
// Atomic file write — temp file + fsync + rename.
if err := fsutil.AtomicWrite(path, blob); err != nil {
    return err
}

// Ed25519 keypair + node-ID derivation.
id, err := crypto.NewIdentity()
sig := id.Sign(msg)
ok := crypto.Verify(id.PublicKey, msg, sig)
```

## Layout

| Package | What it does |
|---|---|
| `fsutil` | `AtomicWrite(path, data)`, `AppendSync(path, data)` — durable file writes. |
| `crypto` | `Identity` — Ed25519 keypair + node-ID derivation, signing, verification. |

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).

