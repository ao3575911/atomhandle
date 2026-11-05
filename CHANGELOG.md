# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-05

### Added

- `did:atom` handle documents signed by an owner Ed25519 key.
- `atom` commands: `keygen`, `claim`, `sign`, `verify`, `checkpoint save`, `serve`.
- `atom-log` append-only transparency log (RFC 6962 / RFC 9162 Merkle tree, signed checkpoints).
- Offline passport verification: document signature, expiry, inclusion proof, checkpoint signature, optional artifact signature.
- Consistency checks against a newer pinned checkpoint.
- Unit tests, property tests, and fuzz tests for the parsers.

[0.1.0]: https://github.com/ao3575911/atomhandle/releases/tag/v0.1.0
