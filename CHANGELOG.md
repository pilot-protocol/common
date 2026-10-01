# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed
- `decision` and `actionhook`. They existed for the hosted control plane,
  which was retired on 2026-10-01. Their last importers (`dataexchange`,
  `eventstream`, `handshake`) dropped them first.

## [v0.1.0]

Initial release.
