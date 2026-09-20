//go:build !windows

package tui

// POSIX-family terminals process ANSI/VT escape sequences natively, so
// the capability probe succeeds and enabling is a no-op whose restore
// is a no-op too. TERM=dumb and output redirection are the caller's
// gate: per ADR D032 piped invocations never reach the TUI in the
// first place.
func vtProbe() bool { return true }

func vtSetup() func() { return func() {} }
