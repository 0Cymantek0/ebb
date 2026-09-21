//go:build windows

package cli

// Advice-string truth for the SEALED-blocked park (Wave 4 gauntlet
// bugs A+B, CLI level). A native handle WITHOUT FILE_SHARE_DELETE is
// held ON the workspace root (the same pin class a shell cd'd into the
// workspace holds — the one the cwd release cannot fix, because it
// belongs to another process). The park must fail blocked while still
// SEALED, its error must name a RECOVERY COMMAND CARRYING A REAL
// OPERATION ID (grepped out and executed by this test), and the named
// command must reconcile the same state to DONE once the holder is
// released.
//
// HAZARD: no cwd change is needed here (the pin is a native handle),
// but the holder must be closed before t.TempDir cleanup can delete
// the tree — it is closed as soon as the user-side remedy would run,
// and again (nil-safe) via defer.

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// holdRootDir opens the directory itself without FILE_SHARE_DELETE —
// the cwd-handle sharing class that pins a directory rename (errno 32).
func holdRootDir(t *testing.T, path string) windows.Handle {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	h, err := windows.CreateFile(p, windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // deliberately NO FILE_SHARE_DELETE
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("CreateFile on the workspace root: %v", err)
	}
	return h
}

func TestSealedBlockedAdviceNamesWorkingDoor(t *testing.T) {
	h := newEHarness(t)

	// Arm the holder the first time the scan probes anything under the
	// root (discovery runs before the lifecycle tail; the handle then
	// outlives every scan and pins the quarantine rename). disarm stops
	// arming PERMANENTLY when the user-side remedy runs — otherwise the
	// resume command's own revalidation scan would re-pin the root.
	var held windows.Handle
	haveHandle := false
	disarm := false
	h.probe.onProbeFile = func(path string) {
		if haveHandle || disarm || !strings.HasPrefix(path, h.wsRoot+string(os.PathSeparator)) {
			return
		}
		held = holdRootDir(t, h.wsRoot)
		haveHandle = true
	}
	defer func() {
		if haveHandle {
			_ = windows.CloseHandle(held)
		}
	}()

	code, stdout, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot)
	if code != ExitInterrupted {
		t.Fatalf("park with a pinned root: code = %d, want %d (exit 5, reconciliation-required); stderr:\n%s", code, ExitInterrupted, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "EBB_E_SHARING_VIOLATION") {
		t.Fatalf("the typed blocker is missing from the error:\n%s", stderr)
	}
	if !haveHandle {
		t.Fatal("the root holder was never armed (probe hook missed)")
	}

	// THE TRUTH TEST: the error must name a recover invocation carrying
	// a REAL operation id, not a placeholder — grep it out and run it.
	advice := regexp.MustCompile("ebb recover ([0-9a-f]{32}) --resume-removal")
	m := advice.FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("the error's safe action does not name `ebb recover <id> --resume-removal` with a concrete id:\n%s", stderr)
	}
	opID := m[1]

	// The durable state is SEALED (the rename never ran) — plain recover
	// reports only, and its report must name the same door.
	h.resetSignalContext()
	code, stdout, stderr = h.run("recover", opID)
	if code != ExitOK {
		t.Fatalf("plain recover of SEALED must report with exit 0, got %d (%s)", code, stderr)
	}
	if !strings.Contains(stdout+stderr, "--resume-removal") {
		t.Fatalf("the plain-recover report does not name the resume door:\n%s%s", stdout, stderr)
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("plain recover removed the root (must be report-only): %v", err)
	}

	// The user releases the holder, then runs the advised command: it
	// must reconcile the SAME state to DONE.
	if err := windows.CloseHandle(held); err != nil {
		t.Fatalf("CloseHandle: %v", err)
	}
	haveHandle = false
	disarm = true
	h.resetSignalContext()
	code, stdout, stderr = h.run("recover", "--json", opID, "--resume-removal")
	if code != ExitOK {
		t.Fatalf("the advised command failed on the state it was named for: code %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "phase") != "DONE" {
		t.Fatalf("phase after the advised command = %v, want DONE (details %v)", env["phase"], env["details"])
	}
	if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
		t.Fatalf("workspace root still exists after the advised command: %v", err)
	}
	if w := h.workspaceRowOf("cliws"); w.Status != "parked" {
		t.Fatalf("workspace status = %s, want parked", w.Status)
	}
}
