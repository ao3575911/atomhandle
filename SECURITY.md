# Security

atomhandle v0.1 lets an agent publish a signed handle and lets someone else check that handle offline against a signed log checkpoint. It is a transparency log, not a certificate authority and not a private channel. Entries are public. There is no revocation list. A verifier that has only one log's word cannot see a fork that log never shows them.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/ao3575911/atomhandle/security/advisories/new). Do not open a public issue, and do not send exploit details to the public tracker. You should hear an acknowledgement within 7 days.

## Threat model

### Log equivocation / split view

The log can sign two different trees of the same size, or extend two divergent histories, and show each client only one of them.

What v0.1 does:

- Every checkpoint is a signed note over origin, size, and root. A verifier checks that signature with a log key it already trusts (`--log-key`, or the key pinned on this machine).
- A passport carries an inclusion proof of the handle document against one checkpoint. `atom verify` recomputes it. The key inside the passport is not trusted on its own; it has to match the trusted key.
- `atom checkpoint save` stores signed checkpoints this client has accepted, plus the consistency proof between the previous pin and the new one. If `verify` later sees a passport whose checkpoint size is in that history, and a newer pin exists, it checks the consistency proofs along the chain.
- Two checkpoints of the same size with different roots are treated as equivocation and verification fails.

What remains:

- If you have never seen the other fork, local checks cannot detect it. Comparing checkpoints with another client (gossip, a witness) is out of scope for v0.1.
- Trust on first use of the log key is weaker than configuring `--log-key` from a channel you already trust. The line printed by `atom serve` is that key.
- A newer pin that is not linked to the passport's tree size fails closed (`verify` errors) rather than pretending the views match.

### Key compromise

**Owner key.** The owner key signs the handle document. Whoever has it can sign a document for a handle that is not yet claimed. It cannot replace a document the log has already accepted for that handle: the log rejects a second claim, and the accepted bytes are covered by the Merkle tree. It also does not let the attacker sign artifacts unless that key is listed in `agents`.

**Agent key.** An agent key signs files. Compromise lets the attacker produce artifact signatures that verify until the document expires. v0.1 has no way to revoke an agent key earlier than `expiry`.

**Log key.** Compromise lets the attacker sign checkpoints for a tree they invented, including a split view. Clients who pin that key will accept those checkpoints. Passports already issued stay verifiable; they do not become retroactively bound to an honest tree. Treat the log key like a root. It is generated on first start and stored in the data directory as `log.skey` (mode `0600`).

Private keys for owners and agents live under `~/.atom` and are written mode `0600`. The directory is mode `0700`.

### Squatting

The first valid claim for a handle wins. There is no recovery, transfer, or admin override in v0.1. A log operator can refuse to append (censorship) but cannot forge an owner signature. Claim names you care about before someone else does. The log does not check that the owner name corresponds to any external identity.

### Replay

- A second submission of the same handle is rejected. The leaf is the exact canonical document, so the signed bytes that were logged are the bytes a passport must contain.
- An artifact signature is over `atomhandle-artifact-v1`, the handle, and the SHA-256 of the file. A signature does not verify for a different file or a different handle. Presenting the same file again is the same statement, not a new one.
- A checkpoint signature covers the origin as well as the size and root, so a note from one log does not verify as a note from another.
- Owner signatures cover a domain-separated canonical document, not a bare hash of an arbitrary message.

### Expiry

`expiry` is inside the owner-signed document. The log cannot extend it without breaking the owner signature, and it rejects a document that is already expired at append time. `atom verify` rejects a document when the current time is not strictly before `expiry`. There is no earlier revocation. Clock skew on `created` is five minutes; there is no skew past `expiry`. A verifier with a wrong clock will get this wrong.

## Out of scope

- Confidentiality of claims. The log stores and serves every accepted document.
- Witnesses, gossip, or a second log.
- Rotation of a log key without a new origin.
- Binding a handle to a DNS name, an account, or a person.
- Availability. A stopped log cannot issue new passports; already issued passports still verify offline until expiry.
