// wave1_carveout_fix_test.go: pins for the adversarial-review fixes of
// the D034 carve-out surface, exercised through the real CLI commands so
// the writer-side wiring is proven end to end:
//
//	F7  the overlay record's link-kind Digest is the sha256 of the exact
//	    .ebb-link sidecar bytes retained in the payload (not "").
//	F8  --carve-out headless consent is pinned to the CLI's displayed-
//	    equivalent candidate set (CarveOutPaths) — the wiring is proven
//	    by the carve EXECUTING through lifecycle's drift gate: a missing
//	    or wrong set refuses the trim instead.
//	F9  the overlay record carries the source permission bits in mode.

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// payloadIDOf returns the fake store's single payload snapshot id.
func payloadIDOf(t *testing.T, h *eHarness) string {
	t.Helper()
	refs, err := h.store.List(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.Tags["ebb-kind"] == "payload" {
			return r.BackendID
		}
	}
	t.Fatal("no payload snapshot")
	return ""
}

// payloadFileOf dumps one file out of the retained payload by its full
// snapshot path (independent readback, never the writer's own decode).
func payloadFileOf(t *testing.T, h *eHarness, suffix string) []byte {
	t.Helper()
	payload := payloadIDOf(t, h)
	ls, err := h.store.Ls(context.Background(), "", "", payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ls {
		if strings.HasSuffix(e.Path, suffix) {
			b, derr := h.store.DumpFile(context.Background(), "", "", payload, e.Path)
			if derr != nil {
				t.Fatal(derr)
			}
			return b
		}
	}
	t.Fatalf("payload carries no file ending in %q", suffix)
	return nil
}

// TestCarveOutLinkSidecarDigestWitnessedCLI (F7): through `ebb trim
// --yes --carve-out`, a preserved LINK inside the outputs is carved and
// its removal-manifest record carries the sha256 of the exact sidecar
// bytes retained in the payload (the link's target text).
func TestCarveOutLinkSidecarDigestWitnessedCLI(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	outside := filepath.Join(h.stateDir, "outside-link-target.txt")
	if err := os.WriteFile(outside, []byte("outside bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkRel := filepath.Join("node_modules", "kept", "outside-link")
	linkPath := filepath.Join(h.wsRoot, linkRel)
	target := relCLITarget(h, linkRel, outside)
	serr := os.Symlink(target, linkPath)
	if serr != nil {
		if runtime.GOOS != "windows" {
			t.Skipf("cannot create symlink: %v", serr)
		}
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, outside).CombinedOutput()
		if jerr != nil {
			t.Skipf("cannot create symlink (%v) or junction (%v: %s)", serr, jerr, out)
		}
	}

	code, _, stderr := h.run("trim", "--groups", "deps", "--yes", "--carve-out", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	plan := latestTrimPlanOf(t, h)
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d", len(plan.Groups))
	}
	wantPath := filepath.ToSlash(linkRel)
	found := false
	for _, r := range plan.Groups[0].OverlayPatches {
		if r.Path != wantPath {
			continue
		}
		found = true
		if r.Kind != "link" {
			t.Fatalf("link record kind = %q", r.Kind)
		}
		sidecar := payloadFileOf(t, h, ".ebb-link")
		if r.Digest == "" {
			t.Fatalf("F7 CONFIRMED: link record digest empty — the sidecar bytes are unwitnessed")
		}
		sum := sha256.Sum256(sidecar)
		if r.Digest != hex.EncodeToString(sum[:]) {
			t.Fatalf("F7 CONFIRMED: link digest %s != sha256 of the retained sidecar bytes %s",
				r.Digest, hex.EncodeToString(sum[:]))
		}
		if r.Mode != 0 {
			t.Errorf("link record mode = %o, want 0", r.Mode)
		}
	}
	if !found {
		t.Fatalf("link not carved: %+v", plan.Groups[0].OverlayPatches)
	}
}

// TestCarveOutRecordsModeAndFileDigestCLI (F9 + F8 wiring): through
// `ebb reclaim --yes --carve-out`, the carved FILE record carries the
// source permission bits (non-zero on every platform) and the file-bytes
// digest; the carve executing at all proves the CLI populated the
// approved path set lifecycle now demands (F8) — a missing set would
// refuse the trim as consent drift.
func TestCarveOutRecordsModeAndFileDigestCLI(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	carved := filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")
	if err := os.Chmod(carved, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fi, err := os.Stat(carved)
	if err != nil {
		t.Fatal(err)
	}
	wantPerm := uint32(fi.Mode().Perm())

	code, _, stderr := h.run("reclaim", "--yes", "--carve-out", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	plan := latestTrimPlanOf(t, h)
	if len(plan.Groups) != 1 || len(plan.Groups[0].OverlayPatches) != 1 {
		t.Fatalf("overlay patches wrong: %+v", plan.Groups[0].OverlayPatches)
	}
	rec := plan.Groups[0].OverlayPatches[0]
	if rec.Path != "node_modules/kept/fix.js" || rec.Kind != "file" {
		t.Fatalf("record shape wrong: %+v", rec)
	}
	if rec.Mode != wantPerm {
		t.Fatalf("F9 CONFIRMED: carved executable recorded mode %o, want the source bits %o", rec.Mode, wantPerm)
	}
	if runtime.GOOS != "windows" && wantPerm != 0o755 {
		t.Fatalf("fixture lost its exec bit before the trim: %o", wantPerm)
	}
	overlay := payloadFileOf(t, h, "overlay/deps/node_modules/kept/fix.js")
	sum := sha256.Sum256(overlay)
	if rec.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("file digest %s != sha256 of the retained overlay bytes %s",
			rec.Digest, hex.EncodeToString(sum[:]))
	}
	if !strings.Contains(stderr, "carved 1 preserved") {
		t.Errorf("stderr must report the carve:\n%s", stderr)
	}
}

// relCLITarget renders the link target as a relative spelling from the
// link's directory (exercises relative link text like the lifecycle
// fixture; falls back to the absolute form when Rel fails).
func relCLITarget(h *eHarness, linkRel, targetAbs string) string {
	linkDir := filepath.Join(h.wsRoot, filepath.Dir(linkRel))
	rel, err := filepath.Rel(linkDir, targetAbs)
	if err != nil {
		return targetAbs
	}
	return rel
}
