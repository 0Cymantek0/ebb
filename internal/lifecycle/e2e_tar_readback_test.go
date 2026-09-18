package lifecycle

// Real-backend conformance for the streaming whole-tree tar readback
// transport (Wave G, W2): per-file and tar paths must produce IDENTICAL
// pass/fail on the same real restic snapshot, the capture path must
// actually be running the tar transport, an aborted consumer must fail
// the real producer, and the per-file vs tar timing delta on this
// fixture is recorded in the log (the §14.3 "avoid one subprocess per
// file" evidence).
//
// Auto-skips without a usable restic binary, like the rest of the e2e
// suite (D013).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/domain"
	"ebb/internal/policy"
)

// buildTarEquivalenceWorkspace builds the §14.3-flavored fixture: ~20
// entries exercising every representable member — regular files, an
// EMPTY file, an empty dir, nested dirs, unicode + a 140-char name, a
// large poorly-compressible file, a junction (outside target), and a
// hardlink group.
func buildTarEquivalenceWorkspace(t *testing.T) (root string, digest map[string]string) {
	t.Helper()
	parent := t.TempDir()
	root = filepath.Join(parent, "ws-tareq")
	digest = map[string]string{}
	put := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		digest[rel] = digestBytes([]byte(body))
	}
	put("a.txt", "tar equivalence alpha\n")
	put("empty.txt", "")
	put("notes.md", "notes that must read back identically through both transports\n")
	put("README.md", "# fixture\n")
	put("package.json", `{"name":"ws-tareq"}`+"\n")
	put("ünïcødé-文件-📄.txt", "unicode member content\n")
	long := strings.Repeat("L", 140)
	put(long+".txt", "long name member content\n")
	put("sub/leaf.txt", "nested leaf\n")
	put("sub/deep/deeper/x.txt", "deeply nested x\n")
	put("sub/more/y1.txt", "y1\n")
	put("sub/more/y2.txt", "y2\n")
	put("sub/more/y3.txt", "y3\n")
	put("z1.txt", "z1\n")
	put("z2.txt", "z2\n")
	// Large poorly-compressible member (real restic chunking).
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := e2eBigFile()
	if err := os.WriteFile(filepath.Join(root, "assets", "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	digest["assets/big.bin"] = digestBytes(big)
	// Empty directory member.
	if err := os.MkdirAll(filepath.Join(root, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Hardlink group: two names, one content (restic duplicates both as
	// full regular members in the tar — probe).
	put("hard-a.txt", "hardlink group content\n")
	if err := os.Link(filepath.Join(root, "hard-a.txt"), filepath.Join(root, "hard-b.txt")); err != nil {
		t.Skipf("cannot create hardlink fixture: %v; link coverage skipped", err)
	}
	digest["hard-b.txt"] = digest["hard-a.txt"]
	// Junction pointing OUTSIDE the workspace (link member in the tar).
	outside := filepath.Join(parent, "outside-target")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "inside.txt"), []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e2eMakeLink(t, filepath.Join(root, "link-out"), outside)
	return root, digest
}

// TestE2EResticTarReadbackEquivalence is the D013 acceptance for the
// transport change: one real capture (whose own §11.4 gate runs the TAR
// transport), then BOTH transports over the same snapshot and readback
// set, then a tampered comparison both must catch, then the real aborted
// consumer. Timing evidence is logged.
func TestE2EResticTarReadbackEquivalence(t *testing.T) {
	e := newE2EEnv(t)

	// The production store must satisfy the seam — this is what routes
	// captures and re-verifications onto the tar transport.
	if _, ok := interface{}(e.store).(domain.TreeTarDumper); !ok {
		t.Fatal("*restic.Store must implement domain.TreeTarDumper (the tar path would never run)")
	}

	root, digests := buildTarEquivalenceWorkspace(t)
	prefix := filepath.Base(root)
	ws := newWSID()

	// One real capture: coverage + FULL readback (tar transport) + seal
	// must pass end to end — this alone is the transport's positive
	// acceptance against real restic, over BOTH tree prefixes (the
	// capture's readback set includes the op-dir documents).
	ctx, cancel := e.opCtx()
	defer cancel()
	res, err := e.coord(nil).Snapshot(ctx, e.vault, root, CaptureOptions{
		WorkspaceName: "ws-tareq", WorkspaceID: ws, Policy: policy.Default("ws-tareq"),
	})
	if err != nil {
		t.Fatalf("snapshot through the tar readback transport: %v", err)
	}
	payload := res.BackendIDs[0]

	// The §11.4 readback set, derived from the TEST's own fixture digests
	// (independent of the scanner and of the backend).
	files := make([]readbackFile, 0, len(digests))
	for rel, d := range digests {
		files = append(files, readbackFile{SnapPath: "/" + prefix + "/" + rel, Digest: d})
	}

	// Timing: tar first, then per-file (the per-file loop benefits from
	// the warmer caches, making the reported delta conservative).
	tarStart := time.Now()
	if err := verifyReadback(ctx, e.store, e.vault.RepoDir, e.vault.Passfile, payload, files); err != nil {
		t.Fatalf("tar transport must pass on the healthy snapshot: %v", err)
	}
	tarDur := time.Since(tarStart)

	perFileStart := time.Now()
	if err := verifyReadbackPerFile(ctx, e.store, e.vault.RepoDir, e.vault.Passfile, payload, files); err != nil {
		t.Fatalf("per-file transport must pass on the same snapshot: %v", err)
	}
	perFileDur := time.Since(perFileStart)
	t.Logf("readback timing on %d files (~%.1f MiB payload): tar=%v per-file=%v (speedup %.1fx; per-file ran on the warmer caches)",
		len(files), float64(e2eBigSize)/(1024*1024), tarDur.Round(time.Millisecond), perFileDur.Round(time.Millisecond),
		float64(perFileDur)/float64(tarDur))

	// Tampered comparison: the same wrong digest must fail BOTH
	// transports with the same named check and the same path named.
	tampered := append([]readbackFile(nil), files...)
	for i := range tampered {
		if tampered[i].SnapPath == "/"+prefix+"/notes.md" {
			tampered[i].Digest = digestBytes([]byte("tampered expectation"))
		}
	}
	for name, verr := range map[string]error{
		"tar":      verifyReadback(ctx, e.store, e.vault.RepoDir, e.vault.Passfile, payload, tampered),
		"per-file": verifyReadbackPerFile(ctx, e.store, e.vault.RepoDir, e.vault.Passfile, payload, tampered),
	} {
		var ev *ErrVerification
		if !errors.As(verr, &ev) || ev.Check != "readback" {
			t.Fatalf("%s transport on tampered digest: %v", name, verr)
		}
		if !strings.Contains(strings.Join(ev.Details, "; "), "/notes.md: readback digest") {
			t.Errorf("%s transport must name the mismatched path: %v", name, ev.Details)
		}
	}

	// Real aborted consumer: the payload (≥1.5 MiB member) exceeds the
	// OS pipe capacity, so the producer is mid-write when the reader
	// stops; Close must fail the producer (probe: "The pipe has been
	// ended.") rather than hang or report success.
	sctx, scancel := context.WithTimeout(context.Background(), time.Minute)
	defer scancel()
	stream, derr := e.store.DumpTreeTar(sctx, e.vault.RepoDir, e.vault.Passfile, payload, "/")
	if derr != nil {
		t.Fatalf("DumpTreeTar: %v", derr)
	}
	buf := make([]byte, 8192)
	if _, rerr := stream.Read(buf); rerr != nil {
		t.Fatalf("first read: %v", rerr)
	}
	if cerr := stream.Close(); cerr == nil {
		t.Fatal("aborted consumer: Close must report the failed producer (a partial stream is never a success, §11.4)")
	} else {
		var se *domain.StoreError
		if !errors.As(cerr, &se) {
			t.Errorf("Close error must be a typed StoreError: %v", cerr)
		}
		t.Logf("aborted consumer surfaced: %v", cerr)
	}

	// The source tree is untouched by `snapshot` (the transport never
	// writes): every fixture byte still matches the test's own digests.
	for rel, d := range digests {
		b, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Fatalf("%s: %v", rel, rerr)
		}
		if got := digestBytes(b); got != d {
			t.Errorf("%s changed on disk after the readback transports", rel)
		}
	}
}
