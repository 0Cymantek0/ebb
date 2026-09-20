// analyse_test.go: engine coverage with a fake GitSurveyor and real
// filesystem fixtures under t.TempDir — category boundaries through an
// injected clock, monorepo aggregation, offline roots, shields, opaque
// symlinks, footprint honesty and parallel correctness. Nothing here
// mutates anything the engine did not create itself; the engine is
// read-only by contract and the tests assert it.

package analyse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// nowFixed is the injected classification clock.
var nowFixed = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// ago returns a time exactly d before the fixed clock.
func ago(d time.Duration) time.Time { return nowFixed.Add(-d) }

// fakeSurvey is a deterministic, concurrency-safe GitSurveyor.
type fakeSurvey struct {
	mu    sync.Mutex
	repos map[string]RepoSummary
	calls int64
}

func (f *fakeSurvey) SurveyRepo(_ context.Context, root string) (RepoSummary, error) {
	atomic.AddInt64(&f.calls, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.repos[root]; ok {
		return r, nil
	}
	return RepoSummary{}, fmt.Errorf("no survey fixture for %s", root)
}

func (f *fakeSurvey) set(root string, r RepoSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repos == nil {
		f.repos = map[string]RepoSummary{}
	}
	f.repos[root] = r
}

// newTestEngine wires the fake survey, the fixed clock and a tiny
// bloated threshold so boundary tests need no multi-GiB fixtures.
func newTestEngine(survey GitSurveyor) *Engine {
	e := NewEngine(survey, nil, nil)
	e.Now = func() time.Time { return nowFixed }
	e.BloatedBytesOverride = 16
	return e
}

// writeFixture writes files (relative slash paths) under dir.
func writeFixture(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// gitRepoFixture seeds the minimal git-boundary fact: a .git directory.
func gitRepoFixture(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// project lookup helper.
func projectByName(t *testing.T, rep Report, name string) Project {
	t.Helper()
	for _, p := range rep.Projects {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("project %q not found in report (%d records)", name, len(rep.Projects))
	return Project{}
}

// makeLink creates a directory link (symlink, falling back to a Windows
// junction via the unprivileged mklink); skip-reporting lets callers
// skip honestly when the platform requires privileges.
func makeLink(t *testing.T, link, target string) error {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return err
	}
	out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if jerr != nil {
		return fmt.Errorf("symlink: %v; junction: %v (%s)", err, jerr, out)
	}
	return nil
}

func TestCategoryBoundaries(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	cases := []struct {
		name string
		age  time.Duration
		want Category
	}{
		{"exactly-active", 14 * 24 * time.Hour, CategoryBloatedActive}, // ≤14d + big footprint
		{"just-past-active", 14*24*time.Hour + time.Hour, CategoryQuiet},
		{"day29", 29 * 24 * time.Hour, CategoryQuiet},
		{"exactly-stale", 30 * 24 * time.Hour, CategoryStale},
		{"exactly-90", 90 * 24 * time.Hour, CategoryStale},
		{"past-90", 90*24*time.Hour + time.Hour, CategoryAbandoned},
	}
	for _, c := range cases {
		dir := filepath.Join(root, c.name)
		gitRepoFixture(t, dir)
		// Footprint above the tiny threshold everywhere; only the age
		// boundary decides.
		writeFixture(t, dir, map[string]string{
			"package.json":               "{}",
			"node_modules/.package-lock": "0123456789abcdef0123",
		})
		survey.set(dir, RepoSummary{IsRepo: true, LastActivityAt: ago(c.age)})
	}
	rep := newTestEngine(survey).Scan(context.Background(), []string{root})
	if rep.Scanned != len(cases) {
		t.Fatalf("scanned = %d, want %d (warnings %v)", rep.Scanned, len(cases), rep.Warnings)
	}
	for _, c := range cases {
		if got := projectByName(t, rep, c.name).Category; got != c.want {
			t.Errorf("%s: category = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestBloatedActiveRequiresFootprint(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	for name, files := range map[string]map[string]string{
		"heavy": {"package.json": "{}", "node_modules/blob": "0123456789abcdef0123"},
		"lean":  {"package.json": "{}", "node_modules/tiny": "x"},
	} {
		dir := filepath.Join(root, name)
		gitRepoFixture(t, dir)
		writeFixture(t, dir, files)
		survey.set(dir, RepoSummary{IsRepo: true, LastActivityAt: ago(2 * 24 * time.Hour)})
	}
	rep := newTestEngine(survey).Scan(context.Background(), []string{root})
	if got := projectByName(t, rep, "heavy").Category; got != CategoryBloatedActive {
		t.Errorf("heavy: category = %q, want bloated-active", got)
	}
	if got := projectByName(t, rep, "lean").Category; got != CategoryActive {
		t.Errorf("lean: category = %q, want active", got)
	}
}

func TestMonorepoAggregation(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "mono")
	gitRepoFixture(t, dir)
	writeFixture(t, dir, map[string]string{
		"pnpm-workspace.yaml":            "packages: ['apps/*', 'packages/*']\n",
		"apps/web/package.json":          "{}",
		"apps/web/node_modules/blob":     "0123456789abcdef0123",
		"packages/ui/package.json":       "{}",
		"packages/ui/node_modules/blob2": "0123456789abcdef0123",
		"packages/ui/node_modules/blob3": "0123456789abcdef0123",
	})
	survey := &fakeSurvey{}
	survey.set(dir, RepoSummary{IsRepo: true, LastActivityAt: ago(time.Hour)})

	rep := newTestEngine(survey).Scan(context.Background(), []string{root})
	if rep.Scanned != 1 {
		t.Fatalf("monorepo must be ONE project record; scanned = %d", rep.Scanned)
	}
	p := projectByName(t, rep, "mono")
	if !p.IsMonorepo {
		t.Error("IsMonorepo not set from pnpm-workspace.yaml")
	}
	// The pnpm-workspace marker also contributes an ecosystem label.
	if len(p.Ecosystems) == 0 {
		t.Error("ecosystem labels missing")
	}
	var got int64
	paths := map[string]bool{}
	for _, o := range p.OutputRoots {
		got += o.Bytes
		paths[o.Path] = true
	}
	if !paths["apps/web/node_modules"] || !paths["packages/ui/node_modules"] {
		t.Errorf("depth-1 output roots not aggregated: %+v", p.OutputRoots)
	}
	if got != p.FootprintBytes || got == 0 {
		t.Errorf("footprint = %d, output sum = %d", p.FootprintBytes, got)
	}
}

func TestCargoWorkspaceBoundary(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "cargo-mono"), map[string]string{
		"Cargo.toml":           "[workspace]\nmembers = [\"crates/*\"]\n",
		"crates/a/Cargo.toml":  "[package]\nname = \"a\"\n",
		"crates/a/target/blob": "0123456789abcdef0123",
	})
	writeFixture(t, filepath.Join(root, "cargo-single"), map[string]string{
		"Cargo.toml":  "[package]\nname = \"s\"\n",
		"src/main.rs": "fn main() {}\n",
	})
	rep := newTestEngine(nil).Scan(context.Background(), []string{root})
	mono := projectByName(t, rep, "cargo-mono")
	single := projectByName(t, rep, "cargo-single")
	if !mono.IsMonorepo {
		t.Error("Cargo.toml with [workspace] must set the monorepo boundary")
	}
	if single.IsMonorepo {
		t.Error("plain Cargo.toml is not a workspace boundary")
	}
	if mono.Category == CategoryOffline || single.Category == CategoryOffline {
		t.Error("fixtures unreadable")
	}
}

func TestOfflineRoot(t *testing.T) {
	live := t.TempDir()
	writeFixture(t, filepath.Join(live, "alive"), map[string]string{"go.mod": "module x\n"})
	missing := filepath.Join(t.TempDir(), "unplugged-drive")

	rep := newTestEngine(nil).Scan(context.Background(), []string{missing, live})
	if len(rep.OfflineRoots) != 1 || rep.OfflineRoots[0] != missing {
		t.Fatalf("offline roots = %v", rep.OfflineRoots)
	}
	p := projectByName(t, rep, "unplugged-drive")
	if !p.Offline || p.Category != CategoryOffline {
		t.Fatalf("offline placeholder wrong: %+v", p)
	}
	if len(p.Notes) == 0 || !strings.HasPrefix(p.Notes[0], NoteOffline) {
		t.Errorf("offline note must carry %s: %v", NoteOffline, p.Notes)
	}
	if rep.Scanned != 2 {
		t.Errorf("scanned = %d, want 2 (offline placeholder + live project)", rep.Scanned)
	}
	if projectByName(t, rep, "alive").Category == CategoryOffline {
		t.Error("live project misclassified offline")
	}
}

func TestShields(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	stale := 60 * 24 * time.Hour
	seed := func(name string, r RepoSummary) {
		dir := filepath.Join(root, name)
		gitRepoFixture(t, dir)
		writeFixture(t, dir, map[string]string{"package.json": "{}", "node_modules/blob": "0123456789abcdef0123"})
		r.IsRepo = true
		r.LastActivityAt = ago(stale)
		survey.set(dir, r)
	}
	seed("clean", RepoSummary{})
	seed("unpushed", RepoSummary{UnpushedCommits: 3})
	seed("conflict", RepoSummary{UnmergedEntries: 2})
	seed("dirty-wt", RepoSummary{IsWorktree: true, WorktreeMain: root, MergedUpstream: true, DirtyWorktree: true})

	rep := newTestEngine(survey).Scan(context.Background(), []string{root})

	clean := projectByName(t, rep, "clean")
	if clean.Shielded() || !clean.ReclaimCandidate() {
		t.Errorf("clean stale project must be a reclaim candidate: %+v", clean)
	}

	unpushed := projectByName(t, rep, "unpushed")
	if !containsStr(unpushed.Shields, ShieldUnpushed) {
		t.Errorf("unpushed shield missing: %v", unpushed.Shields)
	}
	if unpushed.Recommendation.Kind != "push-or-park" {
		t.Errorf("unpushed recommendation = %q, want push-or-park", unpushed.Recommendation.Kind)
	}
	if unpushed.ReclaimCandidate() {
		t.Error("unpushed work must never be a deletion-class batch candidate")
	}
	if rep.Totals.ReclaimableStale == 0 {
		t.Error("clean stale project must count as reclaimable")
	}

	conflict := projectByName(t, rep, "conflict")
	if !containsStr(conflict.Shields, ShieldConflict) || conflict.ReclaimCandidate() {
		t.Errorf("conflict shield not enforced: %+v", conflict)
	}

	// Dirty linked worktree merged upstream: NOT the merged-worktree
	// category (dirty shield), falls through to the age bucket.
	dirty := projectByName(t, rep, "dirty-wt")
	if dirty.Category != CategoryStale {
		t.Errorf("dirty merged worktree category = %q, want stale (dirty shield)", dirty.Category)
	}
	if !containsStr(dirty.Shields, ShieldDirty) {
		t.Errorf("dirty shield missing: %v", dirty.Shields)
	}
	if dirty.PruneCandidate() {
		t.Error("dirty worktree must not be a prune candidate")
	}
}

func TestMergedWorktree(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	dir := filepath.Join(root, "hotfix-login")
	gitRepoFixture(t, dir)
	writeFixture(t, dir, map[string]string{"package.json": "{}", "node_modules/blob": "0123456789abcdef0123"})
	survey.set(dir, RepoSummary{
		IsRepo: true, IsWorktree: true, WorktreeMain: filepath.Join(root, "web-platform"),
		MergedUpstream: true, LastActivityAt: ago(18 * 24 * time.Hour),
	})
	rep := newTestEngine(survey).Scan(context.Background(), []string{root})
	p := projectByName(t, rep, "hotfix-login")
	if p.Category != CategoryMergedWorktree {
		t.Fatalf("category = %q, want merged-worktree", p.Category)
	}
	want := []string{"git", "worktree", "remove", dir}
	if fmt.Sprint(p.Recommendation.Command) != fmt.Sprint(want) {
		t.Errorf("recommendation command = %v, want %v", p.Recommendation.Command, want)
	}
	if !p.PruneCandidate() {
		t.Error("merged+clean worktree must be a prune candidate")
	}
	if rep.Totals.WorktreeBytes == 0 {
		t.Error("worktree bytes not totaled")
	}
}

func TestNonGitStalenessUsesMtime(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "plain")
	writeFixture(t, dir, map[string]string{
		"go.mod":  "module x\n",
		"OLD.txt": "old\n",
		"NEW.txt": "new\n",
	})
	// OLD is ancient, NEW is recent: the NEWEST top-level entry wins.
	oldT := ago(120 * 24 * time.Hour)
	newT := ago(1 * 24 * time.Hour)
	for name, when := range map[string]time.Time{"OLD.txt": oldT, "NEW.txt": newT} {
		if err := os.Chtimes(filepath.Join(dir, name), when, when); err != nil {
			t.Fatal(err)
		}
	}
	rep := newTestEngine(nil).Scan(context.Background(), []string{root})
	p := projectByName(t, rep, "plain")
	if p.Category != CategoryActive {
		t.Fatalf("category = %q, want active (newest mtime is 1d old)", p.Category)
	}
	// Age out the newest entries (including the marker, which carries
	// its creation mtime): the project goes stale by mtime alone.
	for _, name := range []string{"NEW.txt", "go.mod"} {
		when := ago(45 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(dir, name), when, when); err != nil {
			t.Fatal(err)
		}
	}
	rep = newTestEngine(nil).Scan(context.Background(), []string{root})
	if got := projectByName(t, rep, "plain").Category; got != CategoryStale {
		t.Errorf("category = %q, want stale by mtime evidence", got)
	}
}

func TestOpaqueSymlinksNotFollowed(t *testing.T) {
	// Outside target with a marker + heavy folder: a link to it must
	// never be treated as a project.
	outside := t.TempDir()
	writeFixture(t, outside, map[string]string{
		"package.json":      "{}",
		"node_modules/blob": "0123456789abcdef0123",
	})
	root := t.TempDir()
	link := filepath.Join(root, "linked-project")
	if err := makeLink(t, link, outside); err != nil {
		t.Skipf("link creation unprivileged on this machine (%v); opaque-leaf test skipped", err)
	}
	// A real sibling so the root is not empty.
	writeFixture(t, filepath.Join(root, "real"), map[string]string{"go.mod": "module r\n"})

	rep := newTestEngine(nil).Scan(context.Background(), []string{root})
	if _, ok := projectLookup(rep, "linked-project"); ok {
		t.Error("symlinked child became a project record; links must stay opaque")
	}
	foundNote := false
	for _, w := range rep.Warnings {
		if strings.Contains(w, "linked-project") {
			foundNote = true
		}
	}
	if !foundNote {
		t.Errorf("link skip must be noted in warnings: %v", rep.Warnings)
	}

	// A symlinked output root inside a project: opaque, size 0, never
	// followed.
	dir := filepath.Join(root, "real")
	if err := makeLink(t, filepath.Join(dir, "node_modules"), filepath.Join(outside, "node_modules")); err != nil {
		t.Skipf("link creation unprivileged on this machine (%v); opaque-output test skipped", err)
	}
	rep = newTestEngine(nil).Scan(context.Background(), []string{root})
	p := projectByName(t, rep, "real")
	for _, o := range p.OutputRoots {
		if o.Name == "node_modules" && o.Bytes != 0 {
			t.Errorf("symlinked output root was followed or mis-sized: %+v", o)
		}
	}
}

func TestFootprintHonestyLabel(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "proj")
	writeFixture(t, dir, map[string]string{
		"package.json":       "{}",
		"node_modules/a.dat": "0123456789abcdef0123",
		"node_modules/b.dat": "0123456789",
		"target/x.dat":       "01",
	})
	rep := newTestEngine(nil).Scan(context.Background(), []string{root})
	p := projectByName(t, rep, "proj")
	if p.FootprintBytes != 32 {
		t.Errorf("footprint = %d, want 32 (20+10 from node_modules, 2 from target)", p.FootprintBytes)
	}
	if p.FootprintEstimate != FootprintEstimateLabel {
		t.Errorf("estimate label = %q, want the honesty label", p.FootprintEstimate)
	}
	if len(p.OutputRoots) != 2 {
		t.Errorf("output roots = %+v, want node_modules and target", p.OutputRoots)
	}
}

func TestLockProbeSeam(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	free := filepath.Join(root, "free")
	errProbe := filepath.Join(root, "errprobe")
	for _, d := range []string{locked, free, errProbe} {
		writeFixture(t, d, map[string]string{"package.json": "{}", "node_modules/hold": "x"})
	}
	// Push all three out of the active window for a stable category.
	for _, d := range []string{locked, free, errProbe} {
		when := ago(60 * 24 * time.Hour)
		if err := os.Chtimes(filepath.Join(d, "package.json"), when, when); err != nil {
			t.Fatal(err)
		}
	}

	lockedProbe := func(writers []LockWriter, err error) LockProbe {
		return probeFunc(func(paths []string) ([]LockWriter, error) { return writers, err })
	}
	cases := []struct {
		dir     string
		probe   LockProbe
		shield  bool
		wantCat Category
	}{
		{locked, lockedProbe([]LockWriter{{Name: "node.exe", PID: 42}}, nil), true, CategoryStale},
		{free, lockedProbe(nil, nil), false, CategoryStale},
		// A seam error must never produce a [LOCKED] claim.
		{errProbe, lockedProbe(nil, errors.New("restart manager unavailable")), false, CategoryStale},
	}
	for _, c := range cases {
		e := newTestEngine(nil)
		e.Lock = c.probe
		rep := e.Scan(context.Background(), []string{root})
		p := projectByName(t, rep, filepath.Base(c.dir))
		if got := containsStr(p.Shields, ShieldLocked); got != c.shield {
			t.Errorf("%s: [LOCKED] = %v, want %v (shields %v, notes %v)", c.dir, got, c.shield, p.Shields, p.Notes)
		}
		if c.shield && p.ReclaimCandidate() {
			t.Errorf("%s: locked project must be batch-skipped", c.dir)
		}
	}
}

// probeFunc adapts a function to LockProbe.
type probeFunc func(paths []string) ([]LockWriter, error)

func (f probeFunc) InspectWriters(paths []string) ([]LockWriter, error) { return f(paths) }

func TestIsSharingViolationErrnoOnly(t *testing.T) {
	wrapped := func(errno syscall.Errno) error {
		return &os.PathError{Op: "open", Path: "x", Err: errno}
	}
	if !isSharingViolation(wrapped(32)) {
		t.Error("ERROR_SHARING_VIOLATION (32) must be lock evidence")
	}
	if !isSharingViolation(wrapped(11)) {
		t.Error("EAGAIN/EWOULDBLOCK (11) must be lock evidence")
	}
	if isSharingViolation(wrapped(5)) {
		t.Error("ERROR_ACCESS_DENIED (5, read-only file) must NOT be lock evidence")
	}
	if isSharingViolation(&os.PathError{Op: "open", Path: "x", Err: os.ErrPermission}) {
		t.Error("permission errors must never be lock evidence")
	}
	if isSharingViolation(errors.New("boom")) {
		t.Error("non-errno errors must never be lock evidence")
	}
}

func TestParallelCorrectness(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	const n = 60
	for i := 0; i < n; i++ {
		dir := filepath.Join(root, fmt.Sprintf("p%03d", i))
		gitRepoFixture(t, dir)
		writeFixture(t, dir, map[string]string{"package.json": "{}"})
		survey.set(dir, RepoSummary{IsRepo: true, LastActivityAt: ago(time.Duration(i+1) * 24 * time.Hour)})
	}
	e := newTestEngine(survey)
	e.Workers = 8
	rep := e.Scan(context.Background(), []string{root})
	if rep.Scanned != n {
		t.Fatalf("scanned = %d, want %d", rep.Scanned, n)
	}
	if atomic.LoadInt64(&survey.calls) != n {
		t.Errorf("survey calls = %d, want %d", survey.calls, n)
	}
	seen := map[string]bool{}
	for _, p := range rep.Projects {
		if seen[p.Name] {
			t.Errorf("duplicate record %s", p.Name)
		}
		seen[p.Name] = true
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%03d", i)
		if !seen[name] {
			t.Errorf("missing record %s", name)
		}
	}
	// Deterministic order.
	for i := 1; i < len(rep.Projects); i++ {
		if rep.Projects[i-1].Name > rep.Projects[i].Name {
			t.Fatalf("records not sorted by name: %s > %s", rep.Projects[i-1].Name, rep.Projects[i].Name)
		}
	}
}

func TestScanSmoke200Projects(t *testing.T) {
	root := t.TempDir()
	survey := &fakeSurvey{}
	for i := 0; i < 200; i++ {
		dir := filepath.Join(root, fmt.Sprintf("proj%03d", i))
		gitRepoFixture(t, dir)
		writeFixture(t, dir, map[string]string{
			"package.json":         "{}",
			"node_modules/pkg.dat": "0123456789abcdef0123",
		})
		survey.set(dir, RepoSummary{IsRepo: true, LastActivityAt: ago(time.Duration(i%120+1) * 24 * time.Hour)})
	}
	start := time.Now()
	e := newTestEngine(survey)
	rep := e.Scan(context.Background(), []string{root})
	elapsed := time.Since(start)
	if rep.Scanned != 200 {
		t.Fatalf("scanned = %d, want 200 (warnings %v)", rep.Scanned, rep.Warnings)
	}
	sum := 0
	for _, c := range rep.Categories {
		sum += c
	}
	if sum != 200 {
		t.Errorf("category counts sum to %d, want 200 (%v)", sum, rep.Categories)
	}
	// 200 x 20 logical bytes of fixture output must be fully accounted.
	if rep.Totals.FootprintBytes != 200*20 {
		t.Errorf("footprint total = %d, want %d", rep.Totals.FootprintBytes, 200*20)
	}
	t.Logf("200-project scan took %s (correctness assert only; no CI timing gate)", elapsed)
}

// helper: containsStr.
func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// projectLookup finds a record by name; second return is "not found".
func projectLookup(rep Report, name string) (Project, bool) {
	for _, p := range rep.Projects {
		if p.Name == name {
			return p, true
		}
	}
	return Project{}, false
}
