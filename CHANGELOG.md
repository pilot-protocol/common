# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `driver.SendToConfirmed`: sends a datagram like `SendTo` and reports
  whether the daemon sent it, or why not (no route, port policy, ephemeral
  ports exhausted). Against a daemon without the `dgram_confirm` feature it
  falls back to the fire-and-forget send and reports the outcome as unknown.
  `ErrConfirmTimeout` (outcome unknown) and `ErrConfirmQueueTimeout`
  (nothing sent) tell the two timeouts apart.
- `registry/client`: `DeleteNetwork`, `RenameNetwork`, `KickMember`,
  `PromoteMember`, `DemoteMember`, `TransferOwnership`, `SetNetworkPolicy` and
  `SetExprPolicy` sign the request when it names a non-zero node id and a
  signer is configured, as the registry now requires for role-based network
  administration. Requests that name no node (admin-token callers) are sent
  unchanged, and a registry that predates the requirement ignores the
  signature.
- `registry/client`: `SetMemberTagsAs`, `SetNetworkPolicyAs` and
  `SetExprPolicyAs` perform those operations on a node's owner/admin role
  instead of an admin token.

### Removed

- `decision` and `actionhook`. They existed for the hosted control plane,
  which was retired on 2026-10-01. Their last importers (`dataexchange`,
  `eventstream`, `handshake`) dropped them first.

## [v0.1.0]

Initial release.
