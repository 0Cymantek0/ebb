// Package domain holds Ebb's core typed model: identities, entry records,
// routes, and the narrow interfaces that platform/storage adapters implement.
//
// The domain package must not import filesystem-walking, subprocess or UI
// code. It is the contract layer that every other internal package builds
// against; changing it is an architectural event, not a routine edit.
//
// Invariants encoded here (Foundation §6.4): I01 preserve readable unknowns,
// I02 omission requires a recorded route, and route precedence is fixed and
// deterministic.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// ID is a 128-bit random identifier rendered as 32 lowercase hex characters.
// It is deliberately not a UUID-with-dashes to keep path/filename uses clean,
// but is generated from crypto/rand like a UUIDv4.
type ID string

// NewID returns a fresh random identifier.
func NewID() ID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable for a tool whose safety
		// depends on identity; fail loudly rather than degrade.
		panic(fmt.Sprintf("domain: crypto/rand unavailable: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // uuid version 4 shape, kept for tooling
	b[8] = (b[8] & 0x3f) | 0x80
	return ID(hex.EncodeToString(b[:]))
}

// ParseID validates an external identifier string.
func ParseID(s string) (ID, error) {
	if len(s) != 32 {
		return "", errors.New("id must be 32 hex characters")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errors.New("id must be lowercase hex")
		}
	}
	return ID(s), nil
}

func (id ID) String() string { return string(id) }

// Stable identifiers for the durable concepts (Foundation §6.1, §16.1).
// Names and paths are bindings, never primary keys.
type (
	// WorkspaceID identifies a declared development scope across renames.
	WorkspaceID ID
	// SnapshotID identifies one logical captured state (the P/S pair).
	SnapshotID ID
	// OperationID identifies one journaled lifecycle operation.
	OperationID ID
	// VaultID identifies a registered storage boundary.
	VaultID ID
)

// RootID identifies one declared root within a workspace capture.
// Well-known values: "main" (the single owned native root of v1),
// "meta" (the private operation-metadata directory).
type RootID string

const (
	RootMain = RootID("main")
	RootMeta = RootID("meta")
)

// Valid reports whether r is a usable root identifier.
func (r RootID) Valid() bool {
	return r == RootMain || r == RootMeta
}
