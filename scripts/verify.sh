#!/usr/bin/env bash
# scripts/verify.sh — canonical verification entry point for Ebb.
#
# Mirrors the project's standing gate (AGENTS.md §4):
#   1. gofmt -l .        (must list no files)
#   2. go vet ./...
#   3. go test -count=1 ./...
#   4. GOOS=linux go build ./...   (cross-compile check)
#   5. GOOS=linux go vet ./...
#
# Note: `go test -race` is unavailable on the primary dev machine
# (no gcc on PATH, so CGO cannot be enabled); the standing gate
# deliberately omits -race for that reason.
#
# Streams each stage's output, then prints one final PASS/FAIL summary
# line and exits 0 only if every stage passed. Works in Git Bash on
# Windows and on Linux.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || {
	echo "verify.sh: error: not inside a git repository" >&2
	exit 1
}

fail=0

run_stage() { # run_stage <name> <command...>
	local name=$1
	shift
	echo
	echo "==> $name"
	if "$@"; then
		echo "--> $name: PASS"
	else
		echo "--> $name: FAIL"
		fail=1
	fi
}

echo "==> gofmt"
gofmt_out="$(gofmt -l .)"
if [ -n "$gofmt_out" ]; then
	printf '%s\n' "$gofmt_out"
	echo "--> gofmt: FAIL (files above are not gofmt-clean)"
	fail=1
else
	echo "--> gofmt: PASS"
fi

run_stage "go vet ./..." go vet ./...
run_stage "go test -count=1 ./..." go test -count=1 ./...
run_stage "GOOS=linux go build ./..." env GOOS=linux go build ./...
run_stage "GOOS=linux go vet ./..." env GOOS=linux go vet ./...

echo
if [ "$fail" -eq 0 ]; then
	echo "SUMMARY: PASS (all verification stages passed)"
	exit 0
fi
echo "SUMMARY: FAIL (one or more verification stages failed)"
exit 1
