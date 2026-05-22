# common

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
