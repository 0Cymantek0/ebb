// Package vault owns the vault/credential layer of Ebb (Foundation
// §13.1-13.2, §11.5, §16.5): where the unlock secret may live, how it is
// obtained, the local vault registry (vaults.json) and the first-use
// enrollment that mints a vault, its credential-store entry and the
// no-secret recovery locator.
//
// A vault, for the storage layer, is exactly what internal/storage/restic
// needs: a repository directory plus a way to produce the password
// (Foundation §13.1). This package never talks to restic itself; it
// accepts a domain.SnapshotStore and feeds it passfiles.
//
// Secrets discipline (Foundation §13.1, §13.5), enforced everywhere in
// this package:
//
//   - The password NEVER appears in argv, in vaults.json, in the
//     locator, in policy files, in logs, or in routine output. The only
//     sanctioned print is the one-time enrollment recovery print, which
//     is explicitly marked, happens only when the OS credential store is
//     unavailable, and is gated on an interactive terminal plus a user
//     confirmation.
//   - The password reaches the restic CLI exclusively through an
//     ephemeral passfile (WithPassfile), created private, removed and
//     removal-asserted after use (§13.1).
//   - The EBB_VAULT_PASSWORD environment variable is accepted as a
//     source only because environment blocks are not argv and are not
//     logged by this tool; it exists for CI and tests.
//
// Module boundary note (§16.7): mirroring the catalog's vaults table is
// deliberately NOT done here. Vault.CatalogArgs returns the argument
// bundle for catalog.RegisterVault; the higher wiring layer (cli /
// lifecycle) owns that call.
package vault

import "errors"

// ErrNotFound is returned (wrapped with detail) when a registry lookup
// misses: unknown vault id or name, or an empty registry.
var ErrNotFound = errors.New("vault: not found")

// ErrUnsupported reports that an OS credential store is not implemented
// on this platform in v1 (Linux: secret-service integration comes
// later). Callers fall back to the prompt source or, during enrollment,
// the guarded recovery print.
var ErrUnsupported = errors.New("vault: unsupported on this platform")

// ErrRepoDirNotEmpty is returned by Enroll when the target repository
// directory exists and is not empty. Enrolling onto an existing
// directory is never done implicitly: restic init would fail on an
// existing repository anyway, and a non-restic directory may hold user
// data this package must not claim.
var ErrRepoDirNotEmpty = errors.New("vault: repository directory not empty")

// ErrRecoveryUnconfirmed is returned by Enroll when the generated
// password could not be stored in the OS credential store AND the user
// could not interactively confirm that the printed recovery secret was
// stored elsewhere. Enrollment then fails rather than silently creating
// a vault whose only unlock copy is a terminal scrollback (Foundation
// §13.2: enrollment must require confirmation that the recovery secret
// has an independent home).
var ErrRecoveryUnconfirmed = errors.New("vault: recovery secret storage not confirmed")
