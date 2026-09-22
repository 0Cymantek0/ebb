// Command lab/bench is Ebb's first benchmark harness (Foundation §14.4:
// "performance gates, not invented benchmark results"; D013: numbers come
// from the REAL restic binary or there are no numbers).
//
// It is a standalone measurement program, deliberately NOT a test: the
// default `go test ./...` suite stays untouched and green. It drives the
// REAL production packages — internal/inventory, internal/lifecycle,
// internal/restore, internal/storage/restic, internal/platform,
// internal/catalog — exactly as internal/lifecycle's real-backend
// acceptance suite (e2e_reSTORic_test.go) wires them: a real restic
// repository and passfile in a disposable scratch root, a real SQLite
// catalog opened through fresh handles per operation (new-process
// simulation), and the real platform probe. No production package is
// modified; everything lives under lab/bench/.
//
// Isolation: the harness never touches user state. The catalog, vault
// repository, passfile and restic cache all live under --work; APPDATA /
// XDG_CONFIG_HOME / TEMP are re-pointed into the scratch root before any
// component is constructed so even an accidental os.UserConfigDir or
// os.MkdirTemp call cannot escape (the restic adapter additionally builds
// its child environments from scratch). Every destructive call is guarded
// by an assert-under-scratch check that aborts the run without removing
// anything (Foundation §14 safety; the only removal authority exercised
// is lifecycle's own, via Coordinator.Park).
//
// Usage:
//
//	go run ./lab/bench [--restic <path>] [--work <dir>] [--scale 1.0]
//	                   [--out <dir>] [--filter smallfiles,node] [--device "SSD"]
//
// Output: results.json (raw) and report.md (human tables) under --out.
// The curated baseline lives in docs/BENCHMARKS.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
	resticstore "github.com/0Cymantek0/ebb/internal/storage/restic"
	"github.com/0Cymantek0/ebb/internal/version"
)

const benchPassword = "ebb-bench-disposable-password"

func main() {
	resticFlag := flag.String("restic", "", "path to the restic binary (default: PATH lookup; the run is skipped with a message when absent)")
	workFlag := flag.String("work", "", "scratch root for all disposable state (default: a fresh temp dir)")
	scaleFlag := flag.Float64("scale", 1.0, "fixture size multiplier (entry counts and byte sizes scale roughly linearly)")
	outFlag := flag.String("out", "", "results directory (default: lab/bench/results/<UTC-timestamp>/ under the module root)")
	filterFlag := flag.String("filter", "", "comma-separated fixture names to run (default: all)")
	deviceFlag := flag.String("device", "SSD (assumed)", "device class recorded with the run (Foundation §14.4 requires it; no autodetection in v1)")
	keepWork := flag.Bool("keep-work", false, "keep the scratch root after a successful run (default: remove it)")
	flag.Parse()

	if err := run(*resticFlag, *workFlag, *scaleFlag, *outFlag, *filterFlag, *deviceFlag, *keepWork); err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		os.Exit(1)
	}
}

func run(resticArg, workArg string, scale float64, outArg, filter, device string, keepWork bool) error {
	if scale <= 0 || math.IsNaN(scale) || math.IsInf(scale, 0) {
		return fmt.Errorf("--scale must be a positive finite number, got %v", scale)
	}

	// ---- restic binary (skip gracefully, like the e2e suite) ----------
	bin := resticArg
	if bin == "" {
		bin = "restic"
	}
	binPath, err := exec.LookPath(bin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: restic binary %q not usable (%v); nothing to measure.\n", bin, err)
		fmt.Fprintf(os.Stderr, "bench: install restic 0.19.1 or pass --restic <path>.\n")
		return nil
	}
	resticVersion := probeVersion(binPath)

	// ---- scratch root --------------------------------------------------
	work, err := resolveScratch(workArg)
	if err != nil {
		return err
	}
	workAbs, err := canonical(work)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "bench: scratch root %s\n", workAbs)

	// Pin every environment escape hatch into the scratch root BEFORE any
	// component is constructed: user config dirs (defense in depth — the
	// harness passes explicit paths everywhere anyway) and the OS temp root
	// (the restic adapter's private cache dir lands under os.TempDir()).
	for _, d := range []string{"isolated-config", "tmp", "fixtures", "vault", "open-dests"} {
		if err := os.MkdirAll(filepath.Join(workAbs, filepath.FromSlash(d)), 0o700); err != nil {
			return fmt.Errorf("scratch layout: %w", err)
		}
	}
	os.Setenv("APPDATA", filepath.Join(workAbs, "isolated-config"))
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(workAbs, "isolated-config"))
	tmpDir := filepath.Join(workAbs, "tmp")
	os.Setenv("TMP", tmpDir)
	os.Setenv("TEMP", tmpDir)
	os.Setenv("TMPDIR", tmpDir)

	failed := false
	defer func() {
		if failed || keepWork {
			fmt.Fprintf(os.Stderr, "bench: scratch kept at %s\n", workAbs)
			return
		}
		// The only harness-side mass removal, and it is the scratch root
		// itself — guarded like every other destructive call.
		if err := assertUnder(workAbs, workAbs); err == nil {
			_ = os.RemoveAll(workAbs)
		}
	}()

	// ---- results dir ---------------------------------------------------
	outDir := outArg
	if outDir == "" {
		root, rerr := moduleRoot()
		if rerr != nil {
			root = "."
		}
		outDir = filepath.Join(root, "lab", "bench", "results", time.Now().UTC().Format("20060102T150405Z"))
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("results dir: %w", err)
	}

	// ---- shared real components (e2e wiring) ---------------------------
	realStore := resticstore.New(binPath)
	defer realStore.Close() // removes the private restic cache dir (under scratch tmp)
	probe := platform.New()

	repoDir := filepath.Join(workAbs, "vault", "repo")
	passfile := filepath.Join(workAbs, "vault", "repo.pass")
	catPath := filepath.Join(workAbs, "vault", "catalog.db")
	// Safety assertions: every root the harness (or the lifecycle code it
	// drives) may create or destroy lives under the scratch root.
	for _, p := range []string{repoDir, passfile, catPath, filepath.Join(workAbs, "fixtures")} {
		if err := assertUnder(p, workAbs); err != nil {
			return err
		}
	}
	if err := os.WriteFile(passfile, []byte(benchPassword), 0o600); err != nil {
		return fmt.Errorf("passfile: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := realStore.Init(ctx, repoDir, passfile); err != nil {
		return fmt.Errorf("restic init: %w", err)
	}
	repoID, err := realStore.RepoID(ctx, repoDir, passfile)
	if err != nil {
		return fmt.Errorf("restic repo id: %w", err)
	}

	// ---- volume free-space noise floor (Learnings: sample drift first) --
	noise := measureNoiseFloor(probe, workAbs)

	// ---- peak RSS sampler ----------------------------------------------
	stopRSS := startRSSSampler()

	// ---- fixtures -------------------------------------------------------
	names, err := selectedFixtures(filter)
	if err != nil {
		return err
	}
	env := &benchEnv{
		store: &countingStore{SnapshotStore: realStore, TreeTarDumper: realStore}, probe: probe, work: workAbs,
		repoDir: repoDir, passfile: passfile, catPath: catPath,
	}
	runStart := time.Now()
	var results []fixtureResult
	for _, fx := range allFixtures() {
		if !names[fx.name] {
			continue
		}
		fmt.Fprintf(os.Stderr, "bench: fixture %s (scale %.2f)\n", fx.name, scale)
		res, ferr := env.measureFixture(ctx, fx, scale, device)
		if ferr != nil {
			failed = true
			return fmt.Errorf("fixture %s: %w", fx.name, ferr)
		}
		results = append(results, res)
	}
	total := time.Since(runStart)
	peakRSS := stopRSS()

	rep := report{
		Meta: metaInfo{
			TimestampUTC:    time.Now().UTC().Format(time.RFC3339),
			EbbVersion:      version.Version,
			ResticVersion:   resticVersion,
			ResticBinary:    binPath,
			RepoID:          repoID,
			GoVersion:       runtime.Version(),
			GOOS:            runtime.GOOS,
			GOARCH:          runtime.GOARCH,
			CPUModel:        cpuModel(),
			NumCPU:          runtime.NumCPU(),
			DeviceClass:     device,
			Scale:           scale,
			WorkDir:         workAbs,
			OutDir:          outDir,
			TotalRuntimeSec: seconds(total),
			PeakRSSBytes:    peakRSS,
			Notes:           baselineNotes(scale),
		},
		Noise:   noise,
		Results: results,
	}
	if err := writeResults(outDir, &rep); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "bench: done in %s — results in %s\n", total.Round(time.Millisecond), outDir)
	return nil
}

// ---- scratch / safety helpers -------------------------------------------

// resolveScratch creates (or accepts) the disposable scratch root.
func resolveScratch(workArg string) (string, error) {
	if workArg != "" {
		if err := os.MkdirAll(workArg, 0o700); err != nil {
			return "", fmt.Errorf("--work: %w", err)
		}
		return workArg, nil
	}
	dir, err := os.MkdirTemp("", "ebb-bench-")
	if err != nil {
		return "", fmt.Errorf("temp scratch: %w", err)
	}
	return dir, nil
}

// canonical makes an absolute, symlink-resolved spelling of path for the
// containment assertions.
func canonical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, rerr := filepath.EvalSymlinks(abs); rerr == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

// assertUnder aborts (without any removal) unless child lies inside
// parent. Called before every destructive operation.
func assertUnder(child, parent string) error {
	c, err := canonical(child)
	if err != nil {
		return fmt.Errorf("safety: resolve %s: %w", child, err)
	}
	p, err := canonical(parent)
	if err != nil {
		return fmt.Errorf("safety: resolve %s: %w", parent, err)
	}
	rel, rerr := filepath.Rel(p, c)
	if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("safety ABORT: %s resolves outside the scratch root %s", child, parent)
	}
	return nil
}

// removeUnder removes dir only after proving it is under the scratch root.
func removeUnder(dir, scratch string) error {
	if err := assertUnder(dir, scratch); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// moduleRoot walks up from the working directory looking for go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found upward of %s", dir)
		}
		dir = parent
	}
}

// probeVersion returns the restic binary's own version string.
func probeVersion(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	return strings.TrimSpace(string(out))
}

// cpuModel reports the CPU model string per platform, without new deps.
func cpuModel() string {
	if runtime.GOOS == "windows" {
		if id := os.Getenv("PROCESSOR_IDENTIFIER"); id != "" {
			return id
		}
	}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				if _, v, ok := strings.Cut(line, ":"); ok {
					return strings.TrimSpace(v)
				}
			}
		}
	}
	return "unknown"
}

// ---- volume noise floor ---------------------------------------------------

// measureNoiseFloor samples the volume's free space while nothing else in
// this process writes, and reports the observed drift. Park free-space
// deltas smaller than this drift are noise, not signal (Learnings: sample
// drift before measuring; size tolerance from it).
func measureNoiseFloor(probe domain.PlatformProbe, path string) noiseFloor {
	const samples = 8
	var nf noiseFloor
	for i := 0; i < samples; i++ {
		usage, err := probe.VolumeUsage(path)
		if err != nil {
			nf.Error = err.Error()
			return nf
		}
		if i == 0 {
			nf.VolumeID = usage.VolumeID
			nf.Min = usage.FreeToCaller
			nf.Max = usage.FreeToCaller
		}
		if usage.FreeToCaller < nf.Min {
			nf.Min = usage.FreeToCaller
		}
		if usage.FreeToCaller > nf.Max {
			nf.Max = usage.FreeToCaller
		}
		time.Sleep(250 * time.Millisecond)
	}
	nf.Samples = samples
	nf.Drift = nf.Max - nf.Min
	return nf
}

// ---- peak RSS sampler -------------------------------------------------------

// startRSSSampler polls this process's memory until the returned stop
// function is called, then returns the peak Sys observed. runtime.MemStats
// covers the harness process only; restic subprocess memory is invisible
// to it (documented in the report).
func startRSSSampler() func() uint64 {
	var (
		mu   chan struct{}
		peak uint64
	)
	done := make(chan struct{})
	mu = make(chan struct{}, 1)
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				mu <- struct{}{}
				return
			case <-t.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.Sys > peak {
					peak = ms.Sys
				}
			}
		}
	}()
	return func() uint64 {
		close(done)
		<-mu
		return peak
	}
}

// seconds renders a duration as fractional seconds.
func seconds(d time.Duration) float64 { return float64(d) / float64(time.Second) }

// selectedFixtures parses the --filter list into a name set (empty filter
// selects everything).
func selectedFixtures(filter string) (map[string]bool, error) {
	set := map[string]bool{}
	if strings.TrimSpace(filter) == "" {
		for _, fx := range allFixtures() {
			set[fx.name] = true
		}
		return set, nil
	}
	known := map[string]bool{}
	for _, fx := range allFixtures() {
		known[fx.name] = true
	}
	for _, name := range strings.Split(filter, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !known[name] {
			return nil, fmt.Errorf("--filter: unknown fixture %q (known: %s)", name, fixtureNames())
		}
		set[name] = true
	}
	return set, nil
}
