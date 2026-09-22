// Op measurement: drives the REAL lifecycle Coordinator and restore
// Opener over the REAL restic store, exactly as the e2e acceptance suite
// wires them, and times each operation with a wall clock. A thin counting
// wrapper around domain.SnapshotStore records restic invocation counts and
// cumulative subprocess time per operation — the split between subprocess
// time and wall time is what proves readback invocation-boundness.
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/inventory"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/platform"
	"github.com/0Cymantek0/ebb/internal/policy"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// benchEnv carries the shared real components for one run.
type benchEnv struct {
	store    *countingStore
	probe    domain.PlatformProbe
	work     string
	repoDir  string
	passfile string
	catPath  string
}

// opBucket accumulates restic invocation counts and subprocess time for
// one measured operation.
type opBucket struct {
	calls int
	dur   time.Duration
}

// countingStore decorates the real restic store, attributing every
// subprocess to the currently-selected bucket. Sequential use only (the
// harness is single-threaded, like the CLI it models).
//
// TreeTarDumper is embedded SEPARATELY and delegated explicitly: it is
// an optional interface-segregated seam (D019), and a decorator that
// embeds only domain.SnapshotStore hides it — the lifecycle readback
// executor would then silently fall back to the per-file transport and
// the harness would measure the wrong thing (the same
// wrapper-hides-optional-interface lesson as the verified-dir-descent
// probe wrappers; found when the first post-D019 rerun still showed
// ~0.85 s/file readback).
type countingStore struct {
	domain.SnapshotStore
	domain.TreeTarDumper
	cur *opBucket
}

// tarCountingReadCloser attributes the tar dump's duration to the bucket
// when the stream is CLOSED — D019's Close gate is where the producer's
// exit status and full consumption are enforced, so that is when the
// subprocess time is actually known.
type tarCountingReadCloser struct {
	io.ReadCloser
	onClose func()
}

func (r *tarCountingReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.onClose()
	return err
}

func (c *countingStore) bucket() *opBucket {
	if c.cur == nil {
		c.cur = &opBucket{}
	}
	return c.cur
}

func (c *countingStore) record(start time.Time) {
	b := c.bucket()
	b.calls++
	b.dur += time.Since(start)
}

func (c *countingStore) Init(ctx context.Context, dir, passfile string) error {
	t := time.Now()
	err := c.SnapshotStore.Init(ctx, dir, passfile)
	c.record(t)
	return err
}

func (c *countingStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	t := time.Now()
	id, err := c.SnapshotStore.RepoID(ctx, repoDir, passfile)
	c.record(t)
	return id, err
}

func (c *countingStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	t := time.Now()
	ref, err := c.SnapshotStore.Snapshot(ctx, repoDir, baseDir, relPaths, passfile, tags)
	c.record(t)
	return ref, err
}

func (c *countingStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	t := time.Now()
	refs, err := c.SnapshotStore.List(ctx, repoDir, passfile)
	c.record(t)
	return refs, err
}

func (c *countingStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	t := time.Now()
	es, err := c.SnapshotStore.Ls(ctx, repoDir, passfile, snapID)
	c.record(t)
	return es, err
}

func (c *countingStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	t := time.Now()
	b, err := c.SnapshotStore.DumpFile(ctx, repoDir, passfile, snapID, path)
	c.record(t)
	return b, err
}

func (c *countingStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	t := time.Now()
	err := c.SnapshotStore.Restore(ctx, repoDir, passfile, snapID, subtree, dest)
	c.record(t)
	return err
}

func (c *countingStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	t := time.Now()
	err := c.SnapshotStore.Forget(ctx, repoDir, passfile, snapIDs)
	c.record(t)
	return err
}

// DumpTreeTar delegates the streaming tar readback transport (D019) and
// counts it on Close (the producer-exit + full-consumption gate).
func (c *countingStore) DumpTreeTar(ctx context.Context, repoDir, passfile, snapID, treePath string) (io.ReadCloser, error) {
	t := time.Now()
	rc, err := c.TreeTarDumper.DumpTreeTar(ctx, repoDir, passfile, snapID, treePath)
	if err != nil {
		c.record(t)
		return nil, err
	}
	return &tarCountingReadCloser{ReadCloser: rc, onClose: func() { c.record(t) }}, nil
}

// selectBucket points subsequent subprocesses at b.
func (c *countingStore) selectBucket(b *opBucket) { c.cur = b }

// measureFixture runs the full measured-operation sequence for one
// fixture: generate, scan (metadata + hashed), snapshot, explicit
// per-file readback, park (with volume free-space delta), open.
func (e *benchEnv) measureFixture(ctx context.Context, fx fixture, scale float64, device string) (fixtureResult, error) {
	res := fixtureResult{
		Name:        fx.name,
		Description: fx.desc,
		DeviceClass: device,
		Scale:       scale,
	}
	root := filepath.Join(e.work, "fixtures", fx.name)
	if err := assertUnder(root, e.work); err != nil {
		return res, err
	}
	if err := removeUnder(root, e.work); err != nil {
		return res, fmt.Errorf("prepare fixture dir: %w", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return res, fmt.Errorf("fixture dir: %w", err)
	}
	rng := rand.New(rand.NewSource(fixtureSeed(fx.name)))
	t0 := time.Now()
	if err := fx.build(root, scale, rng); err != nil {
		return res, fmt.Errorf("build fixture: %w", err)
	}
	res.GenSec = seconds(time.Since(t0))
	res.Warnings = []string{}

	// ---- scans: metadata-first (inspect) and hashed (capture pass) -----
	t0 = time.Now()
	meta := inventory.Scan(ctx, e.probe, root, inventory.Options{Hash: false})
	if meta.Err != nil {
		return res, fmt.Errorf("metadata scan: %w", meta.Err)
	}
	res.ScanMetaSec = seconds(time.Since(t0))
	t0 = time.Now()
	hashed := inventory.Scan(ctx, e.probe, root, inventory.Options{Hash: true})
	if hashed.Err != nil {
		return res, fmt.Errorf("hashed scan: %w", hashed.Err)
	}
	res.ScanHashSec = seconds(time.Since(t0))

	digests := map[string]string{}
	hlGroups := map[string]bool{}
	for _, en := range hashed.Entries {
		res.EntriesTotal++
		switch en.Kind {
		case domain.KindFile:
			res.Files++
			res.LogicalBytes += en.LogicalSize
			if en.AllocatedSize != nil {
				if res.AllocatedBytes == nil {
					zero := int64(0)
					res.AllocatedBytes = &zero
				}
				// NOTE: per-name allocation; hardlink aliases inside one
				// group each add their (shared) allocation. The shared
				// fixture's hardlink group therefore double-counts here —
				// reported as a caveat, never silently (Foundation §14.1).
				*res.AllocatedBytes += *en.AllocatedSize
			}
			if en.Digest != "" {
				digests[en.Path] = en.Digest
			}
		case domain.KindDir:
			res.Dirs++
		default:
			res.Links++
		}
		if en.HardlinkGroup != "" {
			hlGroups[en.HardlinkGroup] = true
		}
	}
	res.HardlinkGroups = len(hlGroups)
	if len(hashed.Summary.Blocking) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("scan blocking entries: %v", hashed.Summary.Blocking))
	}

	// ---- vault repo baseline -------------------------------------------
	repo0, err := treeSize(e.repoDir)
	if err != nil {
		return res, err
	}
	res.RepoAfterInit = repo0

	wsID := domain.WorkspaceID(domain.NewID())
	pol := policy.Default(fx.name)
	opCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	// ---- snapshot (capture + seal, §12.2 steps 1-5) ---------------------
	var snapRes lifecycle.SnapshotResult
	bucket := &opBucket{}
	e.store.selectBucket(bucket)
	t0 = time.Now()
	err = e.freshCatalog(func(cat *catalog.Catalog) error {
		coord, cerr := lifecycle.New(lifecycle.Dependencies{Store: e.store, Cat: cat, Probe: e.probe})
		if cerr != nil {
			return cerr
		}
		var rerr error
		snapRes, rerr = coord.Snapshot(opCtx, lifecycle.VaultRef{RepoDir: e.repoDir, Passfile: e.passfile}, root,
			lifecycle.CaptureOptions{WorkspaceName: fx.name, WorkspaceID: wsID, Policy: pol})
		return rerr
	})
	res.SnapshotSec = seconds(time.Since(t0))
	res.SnapshotResticCalls, res.SnapshotResticSec = bucket.calls, seconds(bucket.dur)
	if err != nil {
		return res, fmt.Errorf("snapshot op: %w", err)
	}
	res.SnapshotPreserved = snapRes.EntriesPreserved
	res.SnapshotOmitted = snapRes.EntriesOmitted
	res.Warnings = append(res.Warnings, snapRes.Warnings...)
	res.RepoAfterSnapshot, err = treeSize(e.repoDir)
	if err != nil {
		return res, err
	}

	// ---- explicit full readback (the per-file DumpFile transport) ------
	// This is the known scaling risk, measured on its own: dump EVERY file
	// node of the payload snapshot (workspace files plus the three frozen
	// op-dir documents — the same set lifecycle's §11.4 readback walks),
	// hash the bytes, and compare against the independent scan digests.
	bucket = &opBucket{}
	e.store.selectBucket(bucket)
	var readbackFiles int
	var readbackBytes int64
	var digestMismatches []string
	t0 = time.Now()
	nodes, err := e.store.Ls(opCtx, e.repoDir, e.passfile, snapRes.BackendIDs[0])
	if err != nil {
		return res, fmt.Errorf("readback listing: %w", err)
	}
	wsPrefix := "/" + fx.name + "/"
	opPrefix := "/.ebb-op-"
	for _, node := range nodes {
		if node.Kind != domain.KindFile {
			continue
		}
		raw, derr := e.store.DumpFile(opCtx, e.repoDir, e.passfile, snapRes.BackendIDs[0], node.Path)
		if derr != nil {
			return res, fmt.Errorf("readback dump %s: %w", node.Path, derr)
		}
		readbackFiles++
		readbackBytes += int64(len(raw))
		sum := fmt.Sprintf("%x", sha256.Sum256(raw))
		switch {
		case len(node.Path) > len(wsPrefix) && node.Path[:len(wsPrefix)] == wsPrefix:
			want, ok := digests[node.Path[len(wsPrefix):]]
			if !ok {
				digestMismatches = append(digestMismatches, fmt.Sprintf("%s: no independent scan digest", node.Path))
			} else if want != sum {
				digestMismatches = append(digestMismatches, fmt.Sprintf("%s: readback digest mismatch", node.Path))
			}
		case len(node.Path) > len(opPrefix) && node.Path[:len(opPrefix)] == opPrefix:
			// Frozen op-dir documents: read for cost; no independent
			// digest exists outside the snapshot itself.
		default:
			digestMismatches = append(digestMismatches, fmt.Sprintf("%s: unexpected tree node", node.Path))
		}
		if err := opCtx.Err(); err != nil {
			return res, err
		}
	}
	res.ReadbackSec = seconds(time.Since(t0))
	res.ReadbackFiles = readbackFiles
	res.ReadbackBytes = readbackBytes
	res.ReadbackResticCalls, res.ReadbackResticSec = bucket.calls, seconds(bucket.dur)

	// ---- tar readback (the D019 streaming transport) ---------------------
	// The same independent-digest oracle (hashed-scan digests) driven
	// through lifecycle.VerifyReadback — the exported §11.4 executor the
	// CLI's `ebb verify --content` rides, which selects the streaming
	// DumpTreeTar transport when the store implements it. Measured on its
	// own so the two transports are directly comparable columns.
	bucket = &opBucket{}
	e.store.selectBucket(bucket)
	tarFiles := make([]lifecycle.ReadbackFile, 0, len(digests))
	for rel, dg := range digests {
		tarFiles = append(tarFiles, lifecycle.ReadbackFile{SnapPath: wsPrefix + rel, Digest: dg})
	}
	t0 = time.Now()
	if terr := lifecycle.VerifyReadback(opCtx, e.store, e.repoDir, e.passfile, snapRes.BackendIDs[0], tarFiles); terr != nil {
		return res, fmt.Errorf("tar readback: %w", terr)
	}
	res.TarReadbackSec = seconds(time.Since(t0))
	res.TarReadbackFiles = len(tarFiles)
	res.TarReadbackResticCalls, res.TarReadbackResticSec = bucket.calls, seconds(bucket.dur)
	if len(digestMismatches) > 0 {
		return res, fmt.Errorf("readback verification failures: %v", digestMismatches)
	}

	// ---- park (capture + seal + revalidate + removal, §12.2 1-9) -------
	// The destructive call is double-guarded: the fixture root must still
	// resolve inside the scratch root immediately before Park.
	if err := assertUnder(root, e.work); err != nil {
		return res, err
	}
	var parkRes lifecycle.ParkResult
	bucket = &opBucket{}
	e.store.selectBucket(bucket)
	freeBefore, fbErr := e.probe.VolumeUsage(root)
	t0 = time.Now()
	err = e.freshCatalog(func(cat *catalog.Catalog) error {
		coord, cerr := lifecycle.New(lifecycle.Dependencies{Store: e.store, Cat: cat, Probe: e.probe})
		if cerr != nil {
			return cerr
		}
		var rerr error
		parkRes, rerr = coord.Park(opCtx, lifecycle.VaultRef{RepoDir: e.repoDir, Passfile: e.passfile}, root,
			lifecycle.CaptureOptions{
				WorkspaceName: fx.name, WorkspaceID: wsID, Policy: pol,
				Park: true, WriterAssertion: "bench-harness",
			})
		return rerr
	})
	res.ParkSec = seconds(time.Since(t0))
	res.ParkResticCalls, res.ParkResticSec = bucket.calls, seconds(bucket.dur)
	if err != nil {
		return res, fmt.Errorf("park op: %w", err)
	}
	res.ParkAPIDelta = parkRes.VolumeDeltaObserved
	res.ParkEstimated = parkRes.VolumeDeltaEstimated
	res.Warnings = append(res.Warnings, parkRes.Snapshot.Warnings...)
	if fbErr == nil {
		if after, aerr := e.probe.VolumeUsage(root); aerr == nil && after.VolumeID == freeBefore.VolumeID {
			res.ParkFreeDelta = after.FreeToCaller - freeBefore.FreeToCaller
		}
	}
	if _, serr := os.Lstat(root); !os.IsNotExist(serr) {
		return res, fmt.Errorf("park left the fixture root %s in place (stat err = %v)", root, serr)
	}
	res.RepoAfterPark, err = treeSize(e.repoDir)
	if err != nil {
		return res, err
	}

	// ---- open (restore to a fresh destination, §12.5) -------------------
	destParent := filepath.Join(e.work, "open-dests", fx.name)
	if err := os.MkdirAll(destParent, 0o755); err != nil {
		return res, err
	}
	dest := filepath.Join(destParent, fx.name+"-restored")
	if err := assertUnder(dest, e.work); err != nil {
		return res, err
	}
	var openRes restore.Result
	bucket = &opBucket{}
	e.store.selectBucket(bucket)
	t0 = time.Now()
	err = e.freshCatalog(func(cat *catalog.Catalog) error {
		opener, oerr := restore.New(restore.Dependencies{
			Store: e.store, Cat: cat, Probe: platform.New(), CreateLink: platform.CreateLink,
		})
		if oerr != nil {
			return oerr
		}
		var rerr error
		openRes, rerr = opener.Open(opCtx, restore.VaultRef{RepoDir: e.repoDir, Passfile: e.passfile},
			parkRes.Snapshot.SnapshotID, restore.Options{Destination: dest, FilesOnly: true})
		return rerr
	})
	res.OpenSec = seconds(time.Since(t0))
	res.OpenResticCalls, res.OpenResticSec = bucket.calls, seconds(bucket.dur)
	if err != nil {
		return res, fmt.Errorf("open op: %w", err)
	}
	res.OpenEntries = openRes.EntriesRestored
	res.OpenBytes = openRes.BytesRestored
	res.Warnings = append(res.Warnings, openRes.Warnings...)
	if fi, serr := os.Lstat(dest); serr != nil || !fi.IsDir() {
		res.Warnings = append(res.Warnings, fmt.Sprintf("restored destination missing after open (%v)", serr))
	}
	res.RepoAfterOpen, err = treeSize(e.repoDir)
	if err != nil {
		return res, err
	}

	// Derived per-entry overhead (raw divisions, reported as such).
	if res.ReadbackFiles > 0 {
		res.ReadbackPerFileMs = res.ReadbackSec / float64(res.ReadbackFiles) * 1000
	}
	return res, nil
}

// treeSize sums the logical sizes of every regular file under dir (the
// restic repository is a packed-file tree; logical size is the observable
// vault-growth proxy).
func treeSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("size %s: %w", dir, err)
	}
	return total, nil
}

// freshCatalog opens one fresh handle over the shared catalog database
// (new-process simulation, e2e pattern) and closes it after fn returns.
func (e *benchEnv) freshCatalog(fn func(*catalog.Catalog) error) error {
	cat, err := catalog.Open(e.catPath)
	if err != nil {
		return fmt.Errorf("open catalog: %w", err)
	}
	ferr := fn(cat)
	if cerr := cat.Close(); cerr != nil && ferr == nil {
		ferr = fmt.Errorf("close catalog: %w", cerr)
	}
	return ferr
}
