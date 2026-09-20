package lifecycle

// Wave 1 adversarial review fixes for the D034 carve-out surface:
//
//	F7  link overlay sidecar bytes are unwitnessed — the record's Digest
//	    is now the sha256 of the EXACT sidecar target-text bytes, so a
//	    payload-only rewrite of a carved link's target is detectable at
//	    restore time. "" stays "unwitnessed legacy" for old manifests.
//	F8  carve consent was set-level (TOCTOU) — CaptureOptions.CarveOutPaths
//	    pins consent to the exact displayed candidate list; a plan-time
//	    canceller outside the set refuses the group as drift.
//	F9  restored overlays lost the exec bit — the record now carries the
//	    source permission bits in Mode (links record 0; 0 = legacy).
//
// Also pins the frozen JSON wire shape of the amended overlayPatchRecord
// (field order + omitempty semantics) so the restore-side reader and
// this writer stay reconcilable.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOverlayPatchRecordJSONShape pins the amended frozen schema's wire
// form: field order path, copy, digest, kind, mode; mode is OMITTED when
// 0 (links and pre-amendment files); digest is a plain string that is
// per-kind (never omitted — "" means unwitnessed legacy).
func TestOverlayPatchRecordJSONShape(t *testing.T) {
	b, err := json.Marshal(overlayPatchRecord{
		Path:   "node_modules/kept/fix.js",
		Copy:   "overlay/deps/node_modules/kept/fix.js",
		Digest: strings.Repeat("ab", 32), Kind: overlayKindFile, Mode: 0o755,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"path":"node_modules/kept/fix.js","copy":"overlay/deps/node_modules/kept/fix.js","digest":"` +
		strings.Repeat("ab", 32) + `","kind":"file","mode":493}`
	if string(b) != want {
		t.Fatalf("file record wire form drifted:\n got %s\nwant %s", b, want)
	}
	// Mode 0 (link / legacy) is omitted, not serialized as zero.
	b, err = json.Marshal(overlayPatchRecord{
		Path: "node_modules/kept/link", Copy: "overlay/deps/node_modules/kept/link.ebb-link",
		Digest: strings.Repeat("cd", 32), Kind: overlayKindLink,
	})
	if err != nil {
		t.Fatal(err)
	}
	want = `{"path":"node_modules/kept/link","copy":"overlay/deps/node_modules/kept/link.ebb-link","digest":"` +
		strings.Repeat("cd", 32) + `","kind":"link"}`
	if string(b) != want {
		t.Fatalf("link record wire form drifted:\n got %s\nwant %s", b, want)
	}
}

// TestPoCCarveConsentDriftRefused (F8-a): the carve consent is pinned to
// the approved candidate list, not to a boolean. A canceller that shows
// up only in lifecycle's own (later) scan — simulated by approving a set
// that omits it — refuses the group with drift text; nothing is removed
// and no snapshot is claimed. The boolean alone does NOT authorize the
// carve of an unlisted path.
func TestPoCCarveConsentDriftRefused(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "consent-drift")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)
	before := digestTree(t, root)

	// The approved list names fix.js only: note.txt is the "canceller
	// that appeared between the CLI's discovery and lifecycle's scan"
	// (never displayed, never consented to).
	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.CarveOutPaths = []string{"node_modules/kept/fix.js"}
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("CARVE-POC(F8-a) CONFIRMED: unlisted carve candidate not refused: %v", err)
	}
	if !strings.Contains(blocked.Error(), "carve candidate node_modules/kept/deep/note.txt was not part of the approved carve list") {
		t.Fatalf("CARVE-POC(F8-a) CONFIRMED: refusal lacks the honest drift text: %v", blocked)
	}
	if !strings.Contains(blocked.Error(), "deps") {
		t.Fatalf("refusal must name the group: %v", blocked)
	}
	requireSameTree(t, before, digestTree(t, root))
	if snaps, _ := h.coord().cat.ListSnapshots(ws); len(snaps) != 0 {
		t.Fatalf("CARVE-POC(F8-a) CONFIRMED: a drift-refused carve left %d snapshot row(s)", len(snaps))
	}
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Errorf("active ops after drift-refused carve = %d, want 0", n)
	}

	// The boolean with NO set at all is the same drift (the set is the
	// authority, not the flag).
	opts2 := carveOpts(t, ws, "deps")
	opts2.CarveOut = true
	opts2.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts2); !errors.As(err, &blocked) ||
		!strings.Contains(blocked.Error(), "was not part of the approved carve list") {
		t.Fatalf("CARVE-POC(F8-a) CONFIRMED: bare --carve-out (empty set) carved unlisted candidates: %v", err)
	}
	requireSameTree(t, before, digestTree(t, root))
}

// TestPoCCarveApprovedSetMatchesCarves (F8-b): approving exactly the
// candidate set the consent surface derives lets the carve proceed —
// overlay records exist for precisely those paths and nothing else.
func TestPoCCarveApprovedSetMatchesCarves(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "consent-match")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.CarveOutPaths = carveApproveFixture()
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("approved-set carve trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	if len(plan.Groups) != 1 || len(plan.Groups[0].OverlayPatches) != 2 {
		t.Fatalf("CARVE-POC(F8-b) CONFIRMED: approved carve produced %+v", plan.Groups[0].OverlayPatches)
	}
	for _, r := range plan.Groups[0].OverlayPatches {
		switch r.Path {
		case "node_modules/kept/fix.js", "node_modules/kept/deep/note.txt":
		default:
			t.Fatalf("CARVE-POC(F8-b) CONFIRMED: unapproved path %s was carved", r.Path)
		}
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustExist(t, filepath.Join(root, "notes.md"))
}

// TestPoCCarveModeRecordedFromSourceBits (F9): a carved file records the
// source permission bits the platform reports at capture time (0o755
// executables must not come back 0600); links record 0.
func TestPoCCarveModeRecordedFromSourceBits(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "mode-bits")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)
	exec := filepath.Join(root, "node_modules", "kept", "fix.js")
	plain := filepath.Join(root, "node_modules", "kept", "deep", "note.txt")
	if err := os.Chmod(exec, 0o755); err != nil {
		t.Fatalf("chmod exec: %v", err)
	}
	if err := os.Chmod(plain, 0o644); err != nil {
		t.Fatalf("chmod plain: %v", err)
	}
	wantExec := statPermOf(t, exec)
	wantPlain := statPermOf(t, plain)
	if runtime.GOOS != "windows" && (wantExec != 0o755 || wantPlain != 0o644) {
		t.Fatalf("fixture perms drifted: exec=%o plain=%o", wantExec, wantPlain)
	}

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.CarveOutPaths = carveApproveFixture()
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("mode-bits carve trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d", len(plan.Groups))
	}
	for _, r := range plan.Groups[0].OverlayPatches {
		switch r.Path {
		case "node_modules/kept/fix.js":
			if r.Mode != wantExec {
				t.Fatalf("CARVE-POC(F9) CONFIRMED: 0o755 executable recorded mode %o, want %o", r.Mode, wantExec)
			}
		case "node_modules/kept/deep/note.txt":
			if r.Mode != wantPlain {
				t.Fatalf("CARVE-POC(F9) CONFIRMED: 0o644 file recorded mode %o, want %o", r.Mode, wantPlain)
			}
		default:
			t.Fatalf("unexpected carved path %s", r.Path)
		}
		if r.Mode == 0 {
			t.Fatalf("CARVE-POC(F9) CONFIRMED: file %s recorded mode 0 (permission bits unwitnessed)", r.Path)
		}
	}
}

// TestPoCCarveFileDigestStillFileBytes (F7 regression): the file-kind
// Digest semantics did not change with the link amendment — it stays
// the sha256 of the ORIGINAL FILE BYTES (identical to the sealed member
// digest), verified from the sealed payload like an independent reader.
func TestPoCCarveFileDigestStillFileBytes(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "file-digest")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.CarveOutPaths = carveApproveFixture()
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("file-digest carve trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	g := plan.Groups[0]
	memberDigest := map[string]string{}
	for _, m := range g.Members {
		memberDigest[m.Path] = m.Digest
	}
	for _, r := range g.OverlayPatches {
		if r.Kind != overlayKindFile {
			continue
		}
		if r.Digest != memberDigest[r.Path] {
			t.Fatalf("CARVE-POC(F7-regression) CONFIRMED: file digest %s != sealed member digest %s for %s",
				r.Digest, memberDigest[r.Path], r.Path)
		}
		if r.Digest != digestBytes([]byte(carveFix)) && r.Path == "node_modules/kept/fix.js" {
			t.Fatalf("fix.js digest = %s, want the sealed fixture digest", r.Digest)
		}
	}
}

// statPermOf reports a path's permission bits as the platform sees them
// (the same source writeOverlayCopies records from).
func statPermOf(t *testing.T, path string) uint32 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(fi.Mode().Perm())
}
