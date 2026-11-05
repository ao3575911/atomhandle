# did:atom v0.1

Status: draft. This document matches the v0.1 tools in this repository.

A **handle** is a name an agent claims. A **DID** is that name written as a `did:atom` identifier. The owner signs a small JSON document. A transparency log appends the exact bytes to an RFC 6962 / RFC 9162 Merkle tree and signs the tree head. A **passport** packages the document with an inclusion proof and that signed head so a verifier can check it without calling the log again.

Cryptography is SHA-256 (`crypto/sha256`) and Ed25519 (`crypto/ed25519`). Binary fields in documents and proofs are canonical standard base64 (RFC 4648, with padding). The log's own public key uses the signed-note verifier encoding from `golang.org/x/mod/sumdb/note`, not raw base64.

## Handle and DID

```text
handle = "@" label "/" label
label  = alphanum | alphanum middle alphanum
middle = (alphanum | "-")*
alphanum = "a"…"z" | "0"…"9"
```

Each label is 1 to 63 bytes. A hyphen cannot start or end a label. No uppercase.

```text
did = "did:atom:" label "/" label
```

`@adam/researcher` and `did:atom:adam/researcher` are the same name. The DID is the handle without `@`, with the prefix `did:atom:`.

## Handle document

The document is UTF-8 JSON. The signed body is one line, no extra whitespace, keys in this order:

```text
{"handle":"...","did":"...","owner":"...","agents":["..."],"scopes":["..."],"created":"...","expiry":"..."}
```

| Field | Meaning |
| --- | --- |
| `handle` | `@owner/name` |
| `did` | `did:atom:owner/name`, must match `handle` |
| `owner` | base64 of the 32-byte owner Ed25519 public key |
| `agents` | one to sixteen distinct agent public keys, base64, order preserved |
| `scopes` | zero or more scope tokens, sorted, unique |
| `created` | UTC `YYYY-MM-DDTHH:MM:SSZ` |
| `expiry` | same form, strictly after `created` |

A scope matches `[a-z0-9][a-z0-9._:-]{0,62}`. The reference tools do not interpret scopes; they only require this shape. Applications may treat them as claims.

The full document adds the signature as the last field:

```text
...,"signature":"<base64>"}
```

`signature` is 64 bytes, Ed25519 over the exact unsigned JSON prefixed by the ASCII string `atomhandle-document-v1\n` (the prefix includes the newline). The log stores those full canonical bytes and rejects anything else, including the same object with different whitespace or key order.

A document is acceptable to the log when the signature verifies, `created` is not more than five minutes in the future, and `expiry` is still in the future. It is acceptable to a verifier when the signature verifies and the time is strictly before `expiry`, with the same five-minute allowance on `created`.

## Artifact signatures

`atom sign` writes a detached signature: standard base64 of 64 bytes, plus a trailing newline. A raw 64-byte file is also accepted on verify.

The signed message is ASCII:

```text
atomhandle-artifact-v1\n
<handle>\n
<hex SHA-256 of the file>\n
```

The handle is the one in the signed document (`@owner/name`). The signature must verify under one of the document's `agents` keys. The owner key is not an agent key unless it is also listed there. `atom claim` creates a separate agent key and lists it.

## Merkle tree

The log uses the Merkle tree from RFC 9162 §2.1 (the same construction as RFC 6962 §2.1). `HASH` is SHA-256.

- `MTH({}) = SHA-256()`
- `MTH({d}) = SHA-256(0x00 || d)`
- For `n > 1`, let `k` be the largest power of two strictly less than `n`. `MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`

`d` is the canonical document bytes. Inclusion proofs are `PATH` from RFC 9162 §2.1.3. Consistency proofs are `PROOF` from RFC 9162 §2.1.4. Verifiers use the algorithms in §2.1.3.2 and §2.1.4.2. A consistency proof from size 0 is not defined; `first` must be at least 1. When `first == second` the proof is empty and the roots must be equal.

Proof hashes are standard base64 of 32 bytes, ordered as in the RFC (leaf toward root for inclusion).

## Log HTTP API

Base URL in local use: `http://127.0.0.1:8080`.

### `POST /v1/entries`

Body: the canonical document (`Content-Type: application/json`).

Success `200`:

```json
{
  "index": 0,
  "tree_size": 1,
  "leaf_hash": "<base64>",
  "inclusion_proof": [],
  "checkpoint": "<signed note>",
  "log_key": "<note verifier key>"
}
```

`tree_size` is the size immediately after this append. The inclusion proof is for `(index, tree_size)`. `leaf_hash` is `SHA-256(0x00 || document)`.

`400` if the body is not a canonical, currently valid, correctly signed document. `409` with `{"error":"handle already claimed"}` if this handle is already in the log. The first accepted document for a handle wins.

### `GET /v1/entries/{index}`

```json
{"index": 0, "document": {}, "leaf_hash": "<base64>"}
```

`document` is the stored canonical object, not a string. `404` if the index does not exist.

### `GET /v1/proof/inclusion?index=&size=`

Inclusion of that index in the tree of the given size (`index < size <=` current size).

```json
{"index": 0, "size": 1, "leaf_hash": "<base64>", "hashes": []}
```

### `GET /v1/proof/consistency?first=&second=`

Consistency proof between tree sizes `first` and `second` (`0 < first <= second <=` current size).

```json
{"first": 1, "second": 2, "hashes": []}
```

### `GET /v1/checkpoint`

```json
{
  "origin": "atom://127.0.0.1:8080",
  "size": 0,
  "root_hash": "<base64>",
  "checkpoint": "<signed note>",
  "log_key": "<note verifier key>"
}
```

The note is authoritative. `origin`, `size`, and `root_hash` repeat the note body and must match.

Errors are `{"error":"<text>"}`.

## Signed checkpoint

The checkpoint is a [signed note](https://pkg.go.dev/golang.org/x/mod/sumdb/note). The note text is exactly three lines, each ending in `\n`:

```text
<origin>\n
<decimal size>\n
<standard base64 of the 32-byte root>\n
```

`origin` is a non-empty UTF-8 string with no spaces and no `+`. The reference server uses `atom://127.0.0.1:8080`. The size is decimal with no leading zeros (`0` is the empty tree). The note is signed by one Ed25519 key whose note name is the origin. The signature line has the form

```text
— <origin> <base64>\n
```

with an em dash (U+2014), as produced by `note.Sign`. The base64 signature is a 4-byte big-endian key hash followed by the 64-byte Ed25519 signature over the note text. The verifier key string is `<origin>+<8 hex chars>+<base64>`, from `note.GenerateKey`.

The log writes that key the first time it starts (`log.skey` mode `0600`, `log.vkey`, `origin`, and `entries.jsonl` in the data directory). `entries.jsonl` is one JSON object per line: `index`, `handle`, and `document` (base64 of the canonical bytes). Restarting replays the file and rebuilds the tree. A trailing partial line is dropped.

## Passport

`atom claim` writes a JSON file (default `passport.json`):

```json
{
  "version": 1,
  "document": {},
  "index": 0,
  "tree_size": 1,
  "leaf_hash": "<base64>",
  "inclusion_proof": [],
  "checkpoint": "<signed note>",
  "log_key": "<note verifier key>"
}
```

`document` is the canonical object on one line. The other fields are the log's response. Before writing the file, the client checks the leaf hash, the inclusion proof, and the checkpoint signature.

## Offline verification

`atom verify` does not open a network connection. Given a trusted log key (the `--log-key` flag, otherwise the key pinned for this checkpoint's origin under `~/.atom`):

1. Parse the passport. `version` must be 1. `log_key` must equal the trusted key.
2. Parse the document. Check the owner signature, the DID, and the time window above.
3. Parse the checkpoint note with the trusted key. The signer's name must equal the origin line. `tree_size` must equal the checkpoint size, and `index` must be less than that size.
4. Recompute `SHA-256(0x00 || document)` and require it to equal `leaf_hash`.
5. Verify the inclusion proof against the checkpoint root.
6. If an artifact signature was passed, verify it as above.
7. If this machine has a pinned checkpoint history for the origin:
   - A pinned checkpoint of the same size with a different root is equivocation: fail.
   - If the passport's size appears in the history and a later checkpoint was pinned, verify each stored consistency proof up to the newest pin.
   - If a newer pin exists but the passport's size is not in the history, fail. The views are not shown to be consistent.
   - A pin that is older than the passport does not by itself fail verification.

`atom checkpoint save --log URL` fetches the current checkpoint, checks it with the pinned key (trust on first use if none is pinned), and if the tree grew, fetches and checks the consistency proof from the previous pin before appending it. An empty log pins the key and does not record a size-0 checkpoint. A smaller size than the previous pin is a rollback and is rejected.

Trust on first use records whatever key the log presents. Pass `--log-key` with a key you received out of band when that is not good enough. Giving `verify` the key copied out of an untrusted passport is the same as trusting the passport's author.

## Client files

`ATOM_HOME` overrides the default `~/.atom`.

| Path | Content |
| --- | --- |
| `owner.key` | owner seed, mode `0600` |
| `agents/<owner>/<name>.key` | agent seed, mode `0600` |
| `logs/<hex sha256 of origin>/log.vkey` | pinned note verifier key |
| `logs/<hex sha256 of origin>/checkpoints.jsonl` | accepted checkpoints and proofs |
| `server/` | data directory of `atom serve` (unless `--data` or `--dev`) |

Key files are the line `atom-ed25519-v1` and a second line with the standard base64 of the 32-byte seed.
