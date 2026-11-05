# atomhandle

Passports for AI agents: signed did:atom handles, verifiable offline via a Merkle transparency log.

[![CI](https://github.com/ao3575911/atomhandle/actions/workflows/ci.yml/badge.svg)](https://github.com/ao3575911/atomhandle/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ao3575911/atomhandle)](https://github.com/ao3575911/atomhandle/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Definitions

- **Handle** — `@owner/name`, the name an agent claims.
- **DID** — `did:atom:owner/name`, the identifier derived from that handle.
- **Passport** — a file containing the signed handle document, its log index, an inclusion proof, and a signed checkpoint.
- **Checkpoint** — a signed note of the log origin, tree size, and Merkle root.

## Install

```bash
go install github.com/ao3575911/atomhandle/cmd/atom@latest
```

Or download a release binary and check it against `SHA256SUMS`.

## Quickstart

```bash
atom serve &
echo hello > msg.txt
atom claim @you/agent
atom sign --handle @you/agent msg.txt
atom verify passport.json --sig msg.txt.sig msg.txt
```

`atom serve` listens on `127.0.0.1:8080` and stores the log under `~/.atom/server`. The log key is created on first start and printed at startup. `atom claim` writes `passport.json` in the current directory and stores keys under `~/.atom` (private keys mode `0600`). `atom verify` does not contact the log. It uses the log key pinned when you claimed, or `--log-key`.

`atom-log` is the same server. `atom-log --dev` (or `atom serve --dev`) uses `./atom-data` and logs requests. `atom log serve` is an alias of `atom serve`.

## Commands

| Command | What it does |
| --- | --- |
| `atom keygen` | Write an owner key to `~/.atom/owner.key`. `claim` creates one if it is missing. |
| `atom claim @owner/name [--log URL] [--scopes a,b] [--expires 90d] [--out passport.json]` | Sign a handle document, append it to the log, write a passport. |
| `atom sign --handle @owner/name FILE` | Write `FILE.sig`, an Ed25519 signature by that handle's agent key. |
| `atom verify PASSPORT [--sig FILE.sig FILE] [--log-key KEY]` | Check the document, expiry, inclusion proof, checkpoint, and optional artifact offline. |
| `atom checkpoint save --log URL` | Pin the latest signed checkpoint. A later `verify` checks consistency when that pin is newer and a local proof links them. |
| `atom serve` | Run the log. |
| `atom version` | Print the version. |

Default log URL: `http://127.0.0.1:8080`. Set `ATOM_HOME` to override `~/.atom`.

## Develop

```bash
make test
make e2e
```

`make ci` runs formatting, `go vet`, `go test -race`, a short fuzz of each parser, and `scripts/e2e.sh`.

The protocol is [SPEC.md](SPEC.md). The threat model is [SECURITY.md](SECURITY.md). Changes are [CHANGELOG.md](CHANGELOG.md). License: Apache-2.0.
