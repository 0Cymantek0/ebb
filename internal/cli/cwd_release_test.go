// cwd_release_test.go: regression coverage for Wave 4 gauntlet bug A —
// `ebb park` launched with the process working directory INSIDE the
// workspace. On Windows the cwd is an open handle without
// FILE_SHARE_DELETE, so the unfixed build fails the §12.2 step-7
// quarantine rename deterministically (errno 32, gauntlet evidence
// 20260921T194516Z); releaseWorkspaceCwd moves the process out first.
//
// HAZARD: these tests change the PROCESS working directory
// (os.Chdir). They save and restore it, MUST NOT run in parallel
// (no t.Parallel here or in anything that shares the process), and
// must restore the cwd before t.TempDir cleanup runs (function defers
// run before Cleanup callbacks — keep the restore in a defer, never in
// t.Cleanup). On Linux the cwd does not pin a rename, so these pass on
// the unfixed build there; the regression they pin is Windows-specific,
// matching the errno-32 semantics the gauntlet measured.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/pathcanon"
)

// sameDir compares two directory spellings canonically (t.TempDir
// yields 8.3-short forms on Windows while os.Getwd reports long forms —
// the GIT-WT-1 lesson; never compare raw spellings).
func sameDir(a, b string) bool {
	return pathcanon.CanonicalPath(a) == pathcanon.CanonicalPath(b)
}

// withCwd runs fn with the process cwd moved to dir, restoring the
// original cwd afterwards (defer, NOT t.Cleanup — see the file comment).
func withCwd(t *testing.T, dir string, fn func()) {
	t.Helper()
	saved, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(saved); err != nil {
			t.Fatalf("restore cwd %s: %v", saved, err)
		}
	}()
	fn()
}

// TestReleaseWorkspaceCwdNoopOutside: a cwd outside the root is left
// untouched and produces no note.
func TestReleaseWorkspaceCwdNoopOutside(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	withCwd(t, outside, func() {
		var errBuf strings.Builder
		env := newEnvelope("park", "ok")
		releaseWorkspaceCwd(harnessDeps(t), Streams{Out: &errBuf, Err: &errBuf}, root, &env, false)
		if got, _ := os.Getwd(); got != outside {
			t.Fatalf("cwd moved although it was outside the root: %q (want %q)", got, outside)
		}
		if errBuf.Len() != 0 {
			t.Fatalf("note printed for an outside cwd: %q", errBuf.String())
		}
		if len(env.Warnings) != 0 {
			t.Fatalf("warnings recorded for an outside cwd: %v", env.Warnings)
		}
	})
}

// TestReleaseWorkspaceCwdMovesOut: cwd == root and cwd deeper under the
// root both move the process to the root's parent and record the note
// (human: stderr; json: envelope only).
func TestReleaseWorkspaceCwdMovesOut(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, start := range []string{root, deep} {
		withCwd(t, start, func() {
			var errBuf strings.Builder
			env := newEnvelope("park", "ok")
			releaseWorkspaceCwd(harnessDeps(t), Streams{Out: &errBuf, Err: &errBuf}, root, &env, false)
			if got, err := os.Getwd(); err != nil || !sameDir(got, base) {
				t.Fatalf("start %s: cwd after release = %q (%v), want the root parent %q", start, got, err, base)
			}
			if !strings.Contains(errBuf.String(), "moved") {
				t.Fatalf("start %s: human note missing from stderr: %q", start, errBuf.String())
			}
			if len(env.Warnings) != 1 || !strings.Contains(env.Warnings[0], "moved") {
				t.Fatalf("start %s: envelope warning missing: %v", start, env.Warnings)
			}
		})
		// --json: the note rides the envelope only; stderr stays clean.
		withCwd(t, start, func() {
			var errBuf strings.Builder
			env := newEnvelope("park", "ok")
			releaseWorkspaceCwd(harnessDeps(t), Streams{Out: &errBuf, Err: &errBuf}, root, &env, true)
			if errBuf.Len() != 0 {
				t.Fatalf("start %s: json mode wrote to a stream: %q", start, errBuf.String())
			}
			if len(env.Warnings) != 1 {
				t.Fatalf("start %s: json warning missing: %v", start, env.Warnings)
			}
		})
	}
}

// TestParkFromInsideWorkspaceSucceeds is the gauntlet scenario end to
// end: the full CLI park path with the process cwd INSIDE the
// workspace. Unfixed on Windows this fails with EBB_E_SHARING_VIOLATION
// at the quarantine rename and exit 5; fixed it parks (exit 0, DONE,
// root removed) and leaves the process parked outside the workspace.
func TestParkFromInsideWorkspaceSucceeds(t *testing.T) {
	h := newEHarness(t)
	withCwd(t, h.wsRoot, func() {
		code, stdout, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot)
		if code != ExitOK {
			t.Fatalf("park from inside the workspace: code = %d, stderr = %s", code, stderr)
		}
		if stdout != "" {
			t.Fatalf("human mode wrote to stdout: %q", stdout)
		}
		if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
			t.Fatalf("workspace root still exists: %v", err)
		}
		if !strings.Contains(stderr, "moved") {
			t.Errorf("the cwd-release note is missing from stderr:\n%s", stderr)
		}
		if got, _ := os.Getwd(); !sameDir(got, filepath.Dir(h.wsRoot)) {
			t.Errorf("process cwd after park = %q, want the root parent %q", got, filepath.Dir(h.wsRoot))
		}
		if w := h.workspaceRowOf("cliws"); w.Status != "parked" {
			t.Errorf("workspace status = %s, want parked", w.Status)
		}
	})
}

// TestParkFromInsideWorkspaceRelativeArg: the same invocation with a
// RELATIVE path argument (`cd myproject; ebb park .`) — discovery must
// resolve the root to an absolute path BEFORE the cwd moves, and every
// later step must use that absolute path.
func TestParkFromInsideWorkspaceRelativeArg(t *testing.T) {
	h := newEHarness(t)
	withCwd(t, h.wsRoot, func() {
		code, _, stderr := h.run("park", "--assert-writers-stopped", ".")
		if code != ExitOK {
			t.Fatalf("park . from inside the workspace: code = %d, stderr = %s", code, stderr)
		}
		if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
			t.Fatalf("workspace root still exists: %v", err)
		}
	})
}

// TestParkFromInsideWorkspaceJSON: --json mode records the cwd release
// as an envelope warning and never prints the note itself. (Park's
// pre-§17.2 summary lines on the human stream are sanctioned in --json
// mode; the property pinned HERE is that the cwd note is not among
// them — stdout stays the single machine surface.)
func TestParkFromInsideWorkspaceJSON(t *testing.T) {
	h := newEHarness(t)
	withCwd(t, h.wsRoot, func() {
		code, stdout, stderr := h.run("park", "--json", "--assert-writers-stopped", h.wsRoot)
		if code != ExitOK {
			t.Fatalf("code = %d, stderr = %s", code, stderr)
		}
		if strings.Contains(stderr, "moved") || strings.Contains(stderr, "note:") {
			t.Fatalf("the cwd-release note polluted the human stream in --json mode: %q", stderr)
		}
		env := envelopeOf(t, stdout)
		if envString(t, env, "outcome") != "ok" || envString(t, env, "phase") != "DONE" {
			t.Fatalf("envelope head = %v", env)
		}
		warns := envStrings(t, env, "warnings")
		found := false
		for _, w := range warns {
			if strings.Contains(w, "moved") {
				found = true
			}
		}
		if !found {
			t.Fatalf("cwd-release warning missing from the envelope: %v", warns)
		}
	})
}

// TestReclaimEscalationFromInsideWorkspaceSucceeds: the reclaim ->
// park escalation is the second consumer of the shared cwd release.
// The trim stages run with the cwd still inside the root (deleting
// children never needs the root handle released — removal.go), and the
// ESCALATION parks the whole root, which does.
func TestReclaimEscalationFromInsideWorkspaceSucceeds(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	// Approve the trim stage, then the escalation (same shape as
	// TestReclaimInteractiveEscalationExecutesPark, but from inside).
	h.lines = []string{"yes", "yes"}
	withCwd(t, h.wsRoot, func() {
		code, _, stderr := h.run("reclaim", "--target", "1PiB", ".")
		if code != ExitShortfall {
			t.Fatalf("reclaim from inside the workspace: code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
		}
		if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
			t.Fatalf("the escalation did not park the workspace: %v", err)
		}
		for _, want := range []string{"park escalation executed", "moved"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
	})
}

// harnessDeps returns the minimal Deps the cwd release needs (the
// state-dir fallback seam; unused on the success paths).
func harnessDeps(t *testing.T) Deps {
	t.Helper()
	return Deps{StateDir: func() (string, error) { return t.TempDir(), nil }}
}
