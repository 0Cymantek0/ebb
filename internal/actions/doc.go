// Package actions is Ebb's recovery-action subsystem: the only code
// allowed to execute project-approved commands (Foundation §7.3, §9.5).
//
// # No deletion authority
//
// This package must never acquire deletion authority. Foundation §9.5:
// "Actions cannot acquire the source-removal capability. An adapter may
// describe outputs and validation, but only the lifecycle coordinator can
// authorize removing live data." The package exports no function that
// removes or renames files, and no such function may be added.
// TestNoDeletionAuthority (audit_test.go) is the audit tripwire: it fails
// the build if the standard library's file-removal or file-rename calls
// appear anywhere in this package's source (see the test for the exact
// patterns). The JSON approval store deliberately lives in the subpackage
// internal/actions/approvalstore because its atomic document replacement
// requires exactly one rename of Ebb's own metadata file; that rename is
// confined to the store's own document and is outside this package's
// execution authority.
//
// # Execution model
//
// A Definition is a literal argv plus declared working root, inputs,
// outputs, environment allowlist, network declaration, timeout and
// dependencies (Foundation §9.5). Running one is a fixed pipeline:
//
//  1. validate the definition (path contracts, input/output disjointness,
//     acyclic dependency graph);
//  2. resolve argv[0] through PATH and hash the executable;
//  3. digest every declared input under the workspace root;
//  4. require a local approval that exactly matches the action id, argv
//     digest, tool path AND digest, every input digest, the environment
//     allowlist and the network declaration — any drift is a typed
//     ErrApprovalStale naming the drifted field, a missing approval is
//     ErrApprovalRequired, and nothing is ever auto-approved;
//  5. re-validate, then execute the literal argv with no shell, the OS
//     substrate environment plus only the allowlisted keys pulled from
//     the parent process, /dev/null stdin, a context timeout and bounded
//     output capture;
//  6. require every declared output to exist afterwards.
//
// The network declaration is a requirement and approval record, not a
// sandbox (Foundation §9.5); an explicitly requested shell action carries
// a stronger warning marker on every surface (Foundation §7.1) because it
// is arbitrary trusted code.
package actions
