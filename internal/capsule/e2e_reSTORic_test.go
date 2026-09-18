package capsule

// e2e_reSTORic_test.go — the product-level acceptance suite for the
// export protocol: park a fixture workspace with the REAL restic 0.19.1
// backend (through the real lifecycle coordinator), then run Export and
// verify every §15.2 guarantee against the produced capsule with no
// fault-injection doubles: destination resealing with id discovery,
// independent encryption domain, full-content readback from the packaged
// artifact, no-clobber publication, stale-partial refusal, and honest
// failure cleanup. Skips with a reason when restic is not usable
// (EBB_TEST_RESTIC_BIN overrides the lookup target).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/platform"
	"ebb/internal/policy"
	"ebb/internal/restore"
	resticstore "ebb/internal/storage/restic"
)

// e2eBin resolves the restic binary exactly the way the storage
// adapter's own conformance tests do.
func e2eBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("restic binary %q not usable on this machine (%v); real-backend export suite skipped", bin, err)
	}
	return path
}

// e2eWorld is one real-backend fixture: a vault repository, a catalog,
// and a workspace captured through the real lifecycle coordinator.
type e2eWorld struct {
	t        *testing.T
	store    *resticstore.Store
	cat      *catalog.Catalog
	catPath  string
	vaultDir string
	passfile string
	snap     catalog.Snapshot
	ev       restore.Evidence
	srcRepo  string
	wsRoot   string
	outDir   string
	t0       time.Time
}

func newE2EWorld(t *testing.T) *e2eWorld {
	t.Helper()
	store := resticstore.New(e2eBin(t))
	t.Cleanup(store.Close)

	base := t.TempDir()
	w := &e2eWorld{
		t: t, store: store,
		vaultDir: filepath.Join(base, "vault"),
		passfile: filepath.Join(base, "vault.pass"),
		catPath:  filepath.Join(base, "catalog.db"),
		wsRoot:   filepath.Join(base, "ws-capsule"),
		outDir:   filepath.Join(base, "out"),
	}
	if err := os.WriteFile(w.passfile, []byte("capsule-e2e-src-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(w.outDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The fixture workspace: nested files, an empty dir, ~1.2 MiB of
	// poorly-compressible content for realistic chunking.
	files := map[string][]byte{
		"package.json":     []byte(`{"name":"capsule-e2e","version":"1.0.0"}` + "\n"),
		"README.md":        []byte("# capsule e2e fixture\n"),
		"notes/private.md": []byte("private notes must travel inside the capsule\n"),
		"src/deep/main.go": []byte("package main\n\nfunc main() { println(\"capsule\") }\n"),
		"assets/blob.bin":  e2eNoise(1<<20 + 131072),
	}
	for rel, content := range files {
		p := filepath.Join(w.wsRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(w.wsRoot, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A real, verified, sealed snapshot through the real coordinator.
	cat, err := catalog.Open(w.catPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cat.Close() })
	w.cat = cat
	coord, err := lifecycle.New(lifecycle.Dependencies{Store: store, Cat: cat, Probe: platform.New()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	vault := lifecycle.VaultRef{RepoDir: w.vaultDir, Passfile: w.passfile}
	w.t0 = time.Now()
	res, err := coord.Snapshot(ctx, vault, w.wsRoot, lifecycle.CaptureOptions{
		WorkspaceName: "capsule-e2e", Policy: policy.Default("capsule-e2e"),
	})
	if err != nil {
		t.Fatalf("real-restic snapshot: %v", err)
	}
	t.Logf("fixture snapshot %s in %s (preserved %d entries, %s)",
		res.SnapshotID, time.Since(w.t0).Round(time.Millisecond), res.EntriesPreserved, humanBytes(res.PreservedBytes))

	snap, err := cat.GetSnapshot(res.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	w.snap = snap
	ev, err := restore.LoadRetainedEvidence(ctx, store, restore.VaultRef{RepoDir: w.vaultDir, Passfile: w.passfile}, snap.ID, snap)
	if err != nil {
		t.Fatalf("load retained evidence: %v", err)
	}
	w.ev = ev
	srcRepo, err := store.RepoID(ctx, w.vaultDir, w.passfile)
	if err != nil {
		t.Fatal(err)
	}
	w.srcRepo = srcRepo
	return w
}

func e2eNoise(n int) []byte {
	b := make([]byte, n)
	next := uint32(0x85EBCA6B)
	for i := range b {
		next = next*1664525 + 1013904223
		b[i] = byte(next >> 23)
	}
	return b
}

func humanBytes(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// export runs one real Export against the world's snapshot.
func (w *e2eWorld) export(outputPath string, mut func(*Params)) (Result, error) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	params := Params{
		Store:          w.store,
		Snapshot:       w.snap,
		Evidence:       w.ev,
		SourceRepoDir:  w.vaultDir,
		SourcePassfile: w.passfile,
		SourceRepoID:   w.srcRepo,
		OutputPath:     outputPath,
		OperationID:    domain.OperationID(domain.NewID()),
		EbbVersion:     "e2e-test",
		Progress:       os.Stderr,
	}
	if mut != nil {
		mut(&params)
	}
	t0 := time.Now()
	res, err := Export(ctx, params)
	w.t.Logf("export to %s finished in %s (err=%v)", filepath.Base(outputPath), time.Since(t0).Round(time.Millisecond), err)
	return res, err
}

// noScratch asserts no .ebb-* working shapes remain in dir.
func noScratch(t *testing.T, dir string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-") || strings.HasSuffix(d.Name(), ".partial") {
			t.Errorf("scratch artifact %s left behind in %s", d.Name(), dir)
		}
	}
}

func TestE2EResticExportHappyPath(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "project.ebb")

	var phases []string
	var opID string
	res, err := w.export(out, func(p *Params) {
		opID = string(p.OperationID)
		p.Phase = func(step string) error {
			phases = append(phases, step)
			return nil
		}
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	t.Run("publication shape", func(t *testing.T) {
		if _, err := os.Stat(out); err != nil {
			t.Fatalf("capsule not published: %v", err)
		}
		noScratch(t, w.outDir)
		if res.CapsuleBytes <= 0 {
			t.Errorf("capsule bytes = %d", res.CapsuleBytes)
		}
		if res.Passphrase == "" {
			t.Fatal("no passphrase returned for one-time display")
		}
		if res.DestinationPayload == "" || res.DestinationSeal == "" || res.DestinationRepoID == "" {
			t.Errorf("destination identities incomplete: %+v", res)
		}
		want := []string{PhaseCopying, PhaseVerifying, PhasePackaging}
		if strings.Join(phases, ",") != strings.Join(want, ",") {
			t.Errorf("phase steps = %v, want %v", phases, want)
		}
		if res.DestinationPayload == w.snap.PayloadBackendID {
			t.Logf("NOTE: destination payload id equals the source id (ids CAN survive copy; discovery did not rely on it)")
		}
		fi, _ := os.Stat(out)
		t.Logf("capsule %s vs %s preserved payload (%.1f%%)",
			humanBytes(fi.Size()), humanBytes(w.ev.PreservedBytes),
			100*float64(fi.Size())/float64(maxI64(1, w.ev.PreservedBytes)))
	})

	t.Run("source stays sealed, pinned and openable", func(t *testing.T) {
		fresh, err := w.cat.GetSnapshot(w.snap.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !fresh.Pinned {
			t.Error("source snapshot lost its pin (export must never imply forget)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := restore.LoadRetainedEvidence(ctx, w.store,
			restore.VaultRef{RepoDir: w.vaultDir, Passfile: w.passfile}, w.snap.ID, fresh); err != nil {
			t.Fatalf("source evidence unreadable after export: %v", err)
		}
	})

	t.Run("capsule opens only with the generated passphrase", func(t *testing.T) {
		extracted := t.TempDir()
		if err := extractRepository(out, extracted); err != nil {
			t.Fatalf("extract: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// The generated passphrase opens it.
		repoID, err := w.store.RepoID(ctx, extracted, passfileOf(res.Passphrase, t))
		if err != nil {
			t.Fatalf("capsule repo does not open with the generated passphrase: %v", err)
		}
		if repoID != res.DestinationRepoID {
			t.Errorf("extracted repo id %s != destination %s", repoID, res.DestinationRepoID)
		}
		// The SOURCE passphrase must fail (independent encryption domain).
		if _, err := w.store.RepoID(ctx, extracted, w.passfile); err == nil {
			t.Fatal("the source vault passphrase opened the capsule repository — the encryption domain is NOT independent")
		} else {
			var se *domain.StoreError
			if !asStoreErr(err, &se) || se.Class != domain.StoreErrAuth {
				t.Errorf("source-passphrase failure class = %v, want auth", err)
			}
		}
	})

	t.Run("destination seal and content verified from the packaged artifact", func(t *testing.T) {
		extracted := t.TempDir()
		if err := extractRepository(out, extracted); err != nil {
			t.Fatal(err)
		}
		pf := passfileOf(res.Passphrase, t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		refs, err := w.store.List(ctx, extracted, pf)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 {
			t.Fatalf("capsule repo holds %d snapshots, want exactly payload+seal", len(refs))
		}
		// The destination seal names the destination ids and the source
		// manifest digest (F43/§16.4); located through the ebb-op tag the
		// export stamped on the seal snapshot.
		sealPath := "/" + sealDirPrefix + opID + "/" + sealDocName
		var sealRaw []byte
		for _, r := range refs {
			if r.Tags["ebb-kind"] == "seal" && r.Tags["ebb-op"] == opID {
				raw, derr := w.store.DumpFile(ctx, extracted, pf, r.BackendID, sealPath)
				if derr != nil {
					t.Fatalf("dump seal: %v", derr)
				}
				sealRaw = raw
			}
		}
		if sealRaw == nil {
			t.Fatal("no seal snapshot with ebb-kind:seal in the capsule")
		}
		seal, err := parseDestinationSeal(sealRaw)
		if err != nil {
			t.Fatalf("seal strict parse: %v", err)
		}
		if seal.PayloadBackendID != res.DestinationPayload || seal.BackendRepoID != res.DestinationRepoID {
			t.Errorf("seal names repo %s / payload %s; want %s / %s (F43)",
				seal.BackendRepoID, seal.PayloadBackendID, res.DestinationRepoID, res.DestinationPayload)
		}
		if seal.Source.ManifestDigest != w.ev.Manifest.ManifestDigest {
			t.Errorf("seal source manifest digest %s != source evidence digest %s",
				seal.Source.ManifestDigest, w.ev.Manifest.ManifestDigest)
		}
		if seal.Source.LogicalSnapshotID != string(w.snap.ID) {
			t.Errorf("seal source logical id %s != %s", seal.Source.LogicalSnapshotID, w.snap.ID)
		}

		// Payload manifest digest matches the source's, from the capsule.
		manifest, err := w.store.DumpFile(ctx, extracted, pf, res.DestinationPayload,
			"/"+w.ev.OpDirName+"/manifest.json")
		if err != nil {
			t.Fatalf("dump capsule payload manifest: %v", err)
		}
		if got := digestOf(manifest); got != w.ev.Manifest.ManifestDigest {
			t.Errorf("capsule payload manifest digest %s != source %s", got, w.ev.Manifest.ManifestDigest)
		}
		// Full content readback: every retained file's bytes from the
		// capsule match the independent inventory digests.
		for _, e := range w.ev.Retained {
			if e.Kind != domain.KindFile {
				continue
			}
			raw, derr := w.store.DumpFile(ctx, extracted, pf, res.DestinationPayload,
				"/"+w.ev.WsPrefix+"/"+e.Path)
			if derr != nil {
				t.Fatalf("dump %s from capsule: %v", e.Path, derr)
			}
			if got := digestOf(raw); got != e.Digest {
				t.Errorf("capsule content %s digest %s != inventory %s", e.Path, got, e.Digest)
			}
		}
	})
}

func passfileOf(passphrase string, t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "capsule.pass")
	if err := os.WriteFile(p, []byte(passphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func asStoreErr(err error, target **domain.StoreError) bool {
	se, ok := err.(*domain.StoreError)
	if ok {
		*target = se
	}
	return ok
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func TestE2EResticExportStalePartialRefused(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "stale.ebb")
	// Construct the interrupted-export state directly: a recognizable
	// partial (a real capsule from a first run, with the final file
	// absent — exactly what a crash between rename steps leaves).
	first := filepath.Join(w.outDir, "first.ebb")
	if _, err := w.export(first, nil); err != nil {
		t.Fatalf("first export: %v", err)
	}
	b, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out+".partial", b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = w.export(out, nil)
	var pe *ErrPartialExists
	if !asPartial(err, &pe) {
		t.Fatalf("err = %v, want ErrPartialExists", err)
	}
	// The source stays intact and the stale partial is untouched.
	if _, err := os.Stat(out + ".partial"); err != nil {
		t.Fatalf("stale partial was disturbed: %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a capsule was published despite the stale partial refusal")
	}
	noScratchExcept(t, w.outDir, "stale.ebb.partial")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := restore.LoadRetainedEvidence(ctx, w.store,
		restore.VaultRef{RepoDir: w.vaultDir, Passfile: w.passfile}, w.snap.ID, w.snap); err != nil {
		t.Fatalf("source evidence unreadable: %v", err)
	}
}

func noScratchExcept(t *testing.T, dir, keep string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if d.Name() == keep {
			continue
		}
		if strings.HasPrefix(d.Name(), ".ebb-") || strings.HasSuffix(d.Name(), ".partial") {
			t.Errorf("scratch artifact %s left behind in %s", d.Name(), dir)
		}
	}
}

func asPartial(err error, target **ErrPartialExists) bool {
	pe, ok := err.(*ErrPartialExists)
	if ok {
		*target = pe
	}
	return ok
}

func TestE2EResticExportOutputOccupied(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "occupied.ebb")
	if err := os.WriteFile(out, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := w.export(out, nil)
	var oe *ErrOutputOccupied
	if !asOccupied(err, &oe) {
		t.Fatalf("err = %v, want ErrOutputOccupied", err)
	}
	b, _ := os.ReadFile(out)
	if string(b) != "precious" {
		t.Error("occupied output was modified")
	}
	noScratch(t, w.outDir)
}

func asOccupied(err error, target **ErrOutputOccupied) bool {
	oe, ok := err.(*ErrOutputOccupied)
	if ok {
		*target = oe
	}
	return ok
}

func TestE2EResticExportCopyFailureCleansUp(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "failed.ebb")
	// A payload id that is valid 64-hex but absent from the source repo:
	// restic copy exits 0 with an Ignoring line (probe C10) — the typed
	// client-side failure must fire and everything must be cleaned up.
	_, err := w.export(out, func(p *Params) {
		p.Snapshot.PayloadBackendID = strings.Repeat("de", 32)
	})
	if err == nil {
		t.Fatal("copy of an absent snapshot id succeeded (the Ignoring gate failed)")
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Error("a capsule was published from a failed copy")
	}
	noScratch(t, w.outDir)
}

func TestE2EResticExportVerificationCatchesTamperedEvidence(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "tamper.ebb")
	// Tamper the retained inventory digests the export verifies against
	// (simulates a corrupted/tampered working set): the destination
	// readback must fail the named check and publish nothing.
	bad := w.ev
	for i := range bad.Retained {
		if bad.Retained[i].Kind == domain.KindFile {
			bad.Retained[i].Digest = strings.Repeat("ab", 32)
			break
		}
	}
	_, err := w.export(out, func(p *Params) { p.Evidence = bad })
	if !IsVerification(err) {
		t.Fatalf("err = %v, want a failed named check", err)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Error("a capsule was published despite a failed verification check")
	}
	noScratch(t, w.outDir)
}
