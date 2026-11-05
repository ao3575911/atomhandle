#!/bin/sh
# Run the README quickstart against a locally built static binary.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [ -n "${ATOM_BIN:-}" ]; then
	BINDIR=$(CDPATH= cd -- "$(dirname "$ATOM_BIN")" && pwd)
else
	mkdir -p "$ROOT/bin"
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o "$ROOT/bin/atom" ./cmd/atom
	BINDIR="$ROOT/bin"
fi

ldd_out=$(ldd "$BINDIR/atom" 2>&1 || true)
if ! printf '%s\n' "$ldd_out" | grep -E -q 'not a dynamic executable|statically linked'; then
	echo "atom is not a static binary" >&2
	printf '%s\n' "$ldd_out" >&2
	exit 1
fi

for cmd in "atom serve &" "atom claim @you/agent" "atom sign --handle @you/agent msg.txt" "atom verify passport.json --sig msg.txt.sig msg.txt"; do
	if ! grep -q "$cmd" "$ROOT/README.md"; then
		echo "README.md is missing quickstart command: $cmd" >&2
		exit 1
	fi
done

TMP=$(mktemp -d)
LOG="$TMP/serve.log"
PID=""
cleanup() {
	if [ -n "$PID" ]; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT

unset ATOM_HOME || true
export HOME="$TMP/home"
export PATH="$BINDIR:$PATH"
mkdir -p "$HOME" "$TMP/work"
cd "$TMP/work"

atom serve >"$LOG" 2>&1 &
PID=$!

ready=0
i=0
while [ "$i" -lt 50 ]; do
	if curl -fsS "http://127.0.0.1:8080/v1/checkpoint" >/dev/null 2>&1; then
		ready=1
		break
	fi
	if ! kill -0 "$PID" 2>/dev/null; then
		break
	fi
	i=$((i + 1))
	sleep 0.1
done
if [ "$ready" -ne 1 ]; then
	echo "atom serve did not become ready" >&2
	cat "$LOG" >&2 || true
	exit 1
fi

# README quickstart, minus `go install` (this script uses the built binary).
echo hello > msg.txt
atom claim @you/agent
atom sign --handle @you/agent msg.txt
atom verify passport.json --sig msg.txt.sig msg.txt

if atom claim @you/agent; then
	echo "duplicate claim succeeded" >&2
	exit 1
fi
printf 'x' >> msg.txt
if atom verify passport.json --sig msg.txt.sig msg.txt; then
	echo "tampered file verified" >&2
	exit 1
fi
