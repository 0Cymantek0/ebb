// Package version is the single authority for the Ebb build version.
//
// It exists so that exactly one symbol carries the build version and
// every surface — `ebb version` output, receipts and manifests frozen
// by internal/lifecycle, capsule metadata threaded through the CLI —
// reads that one symbol. Before this package existed, cmd/ebb,
// internal/cli and internal/lifecycle each held a hard-coded
// "0.1.0-dev" kept in lockstep by comments only, so a link-time-stamped
// release binary reported the stamped version while recording the
// hard-coded producer version in its recovery records.
//
// Release builds stamp the variable at link time:
//
//	-X github.com/0Cymantek0/ebb/internal/version.Version=<ver>
//
// This spelling works on go1.27 (and earlier) precisely because the
// variable does NOT live in package main: the linker resolves package
// main's path as the literal "main", so -X with an import path only
// matches for non-main packages like this one.
//
// The package is a dependency leaf: it must import nothing, so it can
// never participate in an import cycle, and every other internal
// package may depend on it freely.
package version

// Version is the Ebb build version. The default marks a non-release
// build ("0.1.0-dev"); release builds override it at link time via
// scripts/release.sh (-X github.com/0Cymantek0/ebb/internal/version.Version=<ver>). All
// version-reporting surfaces must read this variable rather than
// keeping their own copy.
var Version = "0.1.0-dev"
