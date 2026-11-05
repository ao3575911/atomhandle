# Contributing

Issues and pull requests are welcome. Bug reports and feature requests use the templates in `.github/ISSUE_TEMPLATE`. Vulnerability reports go through [GitHub Security Advisories](https://github.com/ao3575911/atomhandle/security/advisories/new), not the public tracker. See [SECURITY.md](SECURITY.md).

## Setup

Go 1.26 or newer. Dependencies are the standard library and `golang.org/x`. Signatures are Ed25519 from `crypto/ed25519`. Do not add another crypto implementation.

```bash
go test ./...
go vet ./...
gofmt -w .
make e2e
```

Parser changes should keep the `Fuzz*` tests building. `make fuzz` runs each one for 10 seconds.

## Pull requests

Keep the diff limited to the change. `gofmt` the Go you touch. Say in the pull request how you tested it. Protocol changes belong in [SPEC.md](SPEC.md) and [CHANGELOG.md](CHANGELOG.md) in the same pull request.

This project uses the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).
