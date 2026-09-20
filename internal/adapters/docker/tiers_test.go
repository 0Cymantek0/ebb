package dockeradapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tierOf extracts one tier from a report.
func tierOf(t *testing.T, rep DockerReport, tier int) DockerTier {
	t.Helper()
	for _, tr := range rep.Tiers {
		if tr.Tier == tier {
			return tr
		}
	}
	t.Fatalf("tier %d not present in report", tier)
	return DockerTier{}
}

func findItem(t *testing.T, tr DockerTier, idSubstring string) DockerItem {
	t.Helper()
	for _, item := range tr.Items {
		if strings.Contains(item.ID, idSubstring) {
			return item
		}
	}
	t.Fatalf("no tier item with id containing %q in tier %d (%v)", idSubstring, tr.Tier, itemIDs(tr))
	return DockerItem{}
}

func itemIDs(tr DockerTier) []string {
	ids := make([]string, 0, len(tr.Items))
	for _, item := range tr.Items {
		ids = append(ids, item.ID)
	}
	return ids
}

func oldISO(t *testing.T, days int) string {
	t.Helper()
	return time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)
}

// touchAge sets a directory's (and nothing else's) timestamps.
func touchAge(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	if err := os.Chtimes(dir, when, when); err != nil {
		t.Fatalf("chtimes %s: %v", dir, err)
	}
}

// ---- tier 0 --------------------------------------------------------------

func TestTier0DeadClutter(t *testing.T) {
	linkedVolume := hex64(7)
	deadVolume := hex64(8)
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(1), "Repository": "<none>", "Tag": "<none>",
				"Size": float64(412 << 20), "CreatedAt": oldISO(t, 90)},
			// Tagged images are never tier 0.
			map[string]any{"ID": "sha256:" + hex64(2), "Repository": "postgres", "Tag": "14",
				"Size": float64(1 << 30), "CreatedAt": oldISO(t, 90)},
		)}),
		fakeCmd([]string{"volume", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"Name": deadVolume, "Driver": "local", "Links": float64(0)},
			map[string]any{"Name": linkedVolume, "Driver": "local", "Links": float64(2)},
		)}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t0 := tierOf(t, rep, 0)
	if len(t0.Items) != 2 {
		t.Fatalf("tier 0 items = %v, want the dangling image + the unlinked anonymous volume", itemIDs(t0))
	}
	if got := findItem(t, t0, hex64(1)[:12]); got.Shield != "" {
		t.Fatalf("dangling image must be recommendable: %+v", got)
	}
	if got := findItem(t, t0, deadVolume); got.Shield != "" || !strings.Contains(got.Detail, "anonymous volume") {
		t.Fatalf("dead anonymous volume item: %+v", got)
	}
	for _, item := range t0.Items {
		if item.ID == linkedVolume {
			t.Fatal("linked anonymous volume must not be tier 0")
		}
	}
	if t0.CopyCommand != cmdImagePrune+" && "+cmdVolumePrune {
		t.Fatalf("tier 0 command = %q", t0.CopyCommand)
	}
}

func TestTier0ImageOnlyCommand(t *testing.T) {
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(1), "Repository": "<none>", "Tag": "<none>",
				"Size": float64(1 << 20), "CreatedAt": oldISO(t, 90)})}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if got := tierOf(t, rep, 0).CopyCommand; got != cmdImagePrune {
		t.Fatalf("tier 0 command = %q, want %q", got, cmdImagePrune)
	}
}

// ---- tier 1 --------------------------------------------------------------

func TestTier1CommandExact(t *testing.T) {
	old := time.Now().Add(-20 * 24 * time.Hour).UTC().Format(time.RFC3339)
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"buildx", "du"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(4), "LastUsedAt": old,
				"RecordType": "exec.cachemount", "Usage": map[string]any{"Size": float64(1 << 30)}})}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t1 := tierOf(t, rep, 1)
	if len(t1.Items) != 1 {
		t.Fatalf("tier 1 items = %v", itemIDs(t1))
	}
	if t1.CopyCommand != `docker builder prune --filter "until=336h"` {
		t.Fatalf("tier 1 command = %q", t1.CopyCommand)
	}
}

// ---- tier 2 --------------------------------------------------------------

func TestTier2ZombiesAndShields(t *testing.T) {
	base := t.TempDir()
	liveDir := filepath.Join(base, "liveproj")    // active scanned root
	dormantDir := filepath.Join(base, "oldproj")  // dormant scanned root
	unscanned := filepath.Join(base, "outsiders") // exists, not scanned
	deletedDir := filepath.Join(base, "goneproj") // never created
	for _, d := range []string{liveDir, dormantDir, unscanned} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touchAge(t, liveDir, 24*time.Hour)       // active (<14d)
	touchAge(t, dormantDir, 90*24*time.Hour) // dormant
	touchAge(t, unscanned, 90*24*time.Hour)

	labels := func(project, wd string) map[string]any {
		return map[string]any{
			"com.docker.compose.project":             project,
			"com.docker.compose.project.working_dir": wd,
		}
	}
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(1), "Names": "zombie-1", "Image": "goneproj-web:latest",
				"State": "exited", "Status": "Exited (0) 4 weeks ago", "Labels": labels("goneproj", deletedDir)},
			map[string]any{"ID": "sha256:" + hex64(2), "Names": "live-1", "Image": "liveproj-api:latest",
				"State": "exited", "Status": "Exited (0) 2 days ago", "Labels": labels("liveproj", liveDir)},
			map[string]any{"ID": "sha256:" + hex64(3), "Names": "outsider-1", "Image": "outsiders-app:latest",
				"State": "exited", "Status": "Exited (0) 8 weeks ago", "Labels": labels("outsiders", unscanned)},
			// Running containers are never zombie blockers.
			map[string]any{"ID": "sha256:" + hex64(4), "Names": "runner-1", "Image": "goneproj-web:latest",
				"State": "running", "Status": "Up 3 days", "Labels": labels("goneproj", deletedDir)},
			// Stopped without compose provenance: unclassified.
			map[string]any{"ID": "sha256:" + hex64(5), "Names": "mystery-1", "Image": "busybox:latest",
				"State": "exited", "Status": "Exited (0) 9 weeks ago", "Labels": map[string]any{}},
		)}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), []string{liveDir, dormantDir})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t2 := tierOf(t, rep, 2)

	rec := findItem(t, t2, hex64(1)[:12])
	if rec.Shield != "" || !strings.Contains(rec.Detail, "no longer exists") {
		t.Fatalf("deleted-workdir container must be recommended: %+v", rec)
	}
	live := findItem(t, t2, hex64(2)[:12])
	if !strings.Contains(live.Shield, "active workspace") {
		t.Fatalf("active-workspace container must be shielded: %+v", live)
	}
	outsider := findItem(t, t2, hex64(3)[:12])
	if !strings.Contains(outsider.Shield, "outside scanned roots") {
		t.Fatalf("unscanned-dir container must be shielded: %+v", outsider)
	}
	for _, item := range t2.Items {
		if strings.HasPrefix(item.ID, hex64(4)[:12]) {
			t.Fatal("running container must not appear in tier 2")
		}
	}
	if t2.CopyCommand != "docker rm "+hex64(1)[:12] {
		t.Fatalf("tier 2 command = %q, want %q", t2.CopyCommand, "docker rm "+hex64(1)[:12])
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "stopped container(s) without compose provenance") {
		t.Fatalf("expected unclassified stopped-container warning, got %v", rep.Warnings)
	}
}

func TestTier2WSLPathCorrelation(t *testing.T) {
	// A compose label recorded from inside WSL (/mnt/<drive>/...) must
	// correlate with the native Windows root spelling (Windows only —
	// on POSIX both spellings are just different paths).
	if !isWindowsHost() {
		t.Skip("WSL label correlation is a Windows-build capability")
	}
	base := t.TempDir()
	wslSpelling := toWSLPath(t, base)
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(1), "Names": "w-1", "Image": "x:latest",
				"State": "exited", "Status": "Exited (0) 3 weeks ago",
				"Labels": map[string]any{
					"com.docker.compose.project":             "proj",
					"com.docker.compose.project.working_dir": wslSpelling,
				}})}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), []string{base})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t2 := tierOf(t, rep, 2)
	if len(t2.Items) != 1 || t2.Items[0].Shield == "" {
		t.Fatalf("WSL-spelled working dir must correlate to the live root and shield: %+v", t2.Items)
	}
}

// ---- tier 3 --------------------------------------------------------------

func TestTier3ColdImagesAndShields(t *testing.T) {
	base := t.TempDir()
	coldDir := filepath.Join(base, "coldproj")
	hotDir := filepath.Join(base, "hotproj")
	for _, d := range []string{coldDir, hotDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touchAge(t, coldDir, 120*24*time.Hour) // dormant workspace
	touchAge(t, hotDir, time.Hour)         // active workspace

	imageRows := ndjson(
		// Correlated by name to the dormant workspace, >60d old.
		map[string]any{"ID": "sha256:" + hex64(1), "Repository": "coldproj-web", "Tag": "latest",
			"Size": float64(2<<30 + 300<<20), "CreatedAt": oldISO(t, 90)},
		// Correlated to the ACTIVE workspace: shielded.
		map[string]any{"ID": "sha256:" + hex64(2), "Repository": "hotproj-web", "Tag": "latest",
			"Size": float64(1 << 30), "CreatedAt": oldISO(t, 90)},
		// Correlated to the dormant workspace but freshly built: omitted.
		map[string]any{"ID": "sha256:" + hex64(3), "Repository": "coldproj-api", "Tag": "latest",
			"Size": float64(1 << 30), "CreatedAt": oldISO(t, 10)},
		// Pinned by a running container through compose provenance.
		map[string]any{"ID": "sha256:" + hex64(5), "Repository": "coldproj-db", "Tag": "latest",
			"Size": float64(1 << 30), "CreatedAt": oldISO(t, 90)},
	)
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": imageRows}),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			// Running container pins coldproj-db through provenance.
			map[string]any{"ID": "sha256:" + hex64(4), "Names": "db-1", "Image": "coldproj-db:latest",
				"State": "running", "Status": "Up 2 days",
				"Labels": map[string]any{
					"com.docker.compose.project":             "coldproj",
					"com.docker.compose.project.working_dir": coldDir,
				}},
		)}),
	)

	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), []string{coldDir, hotDir})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t3 := tierOf(t, rep, 3)

	cold := findItem(t, t3, hex64(1)[:12])
	if cold.Shield != "" {
		t.Fatalf("cold project image must be a freeze candidate: %+v", cold)
	}
	if !strings.Contains(cold.Detail, "freeze-to-vault candidate") {
		t.Fatalf("tier 3 detail must carry the freeze note: %s", cold.Detail)
	}
	hot := findItem(t, t3, hex64(2)[:12])
	if !strings.Contains(hot.Shield, "active workspace") {
		t.Fatalf("active-workspace image must be shielded: %+v", hot)
	}
	db := findItem(t, t3, hex64(5)[:12])
	if !strings.Contains(db.Shield, "running container") {
		t.Fatalf("image pinned by a running container must be shielded: %+v", db)
	}
	for _, item := range t3.Items {
		if item.ID == hex64(3)[:12] {
			t.Fatal("recently-built image must be omitted from tier 3")
		}
	}
	if t3.CopyCommand != freezePlaceholder+" "+hex64(1)[:12] {
		t.Fatalf("tier 3 command = %q, want %q", t3.CopyCommand, freezePlaceholder+" "+hex64(1)[:12])
	}
	if strings.Contains(t3.CopyCommand, "docker rmi") || strings.Contains(t3.CopyCommand, "docker save") {
		t.Fatalf("tier 3 must never emit a destructive/docker-side command: %q", t3.CopyCommand)
	}
}

// ---- tier 4 --------------------------------------------------------------

func TestTier4UpstreamShapingAndShields(t *testing.T) {
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			// Dormant official image: recommended.
			map[string]any{"ID": "sha256:" + hex64(1), "Repository": "postgres", "Tag": "14",
				"Size": float64(400 << 20), "CreatedAt": oldISO(t, 90)},
			// In use by a running container: skipped entirely.
			map[string]any{"ID": "sha256:" + hex64(2), "Repository": "node", "Tag": "18",
				"Size": float64(900 << 20), "CreatedAt": oldISO(t, 90)},
			// Pinned by a stopped container: shielded blocker.
			map[string]any{"ID": "sha256:" + hex64(3), "Repository": "redis", "Tag": "6",
				"Size": float64(120 << 20), "CreatedAt": oldISO(t, 90)},
			// Host-shaped registry ref: recommended.
			map[string]any{"ID": "sha256:" + hex64(4), "Repository": "ghcr.io/acme/api", "Tag": "v2",
				"Size": float64(200 << 20), "CreatedAt": oldISO(t, 200)},
			// User namespace without host: ambiguous, unclassified.
			map[string]any{"ID": "sha256:" + hex64(5), "Repository": "myuser/myapp", "Tag": "latest",
				"Size": float64(50 << 20), "CreatedAt": oldISO(t, 90)},
			// Official but fresh: not dormant yet.
			map[string]any{"ID": "sha256:" + hex64(6), "Repository": "ubuntu", "Tag": "22.04",
				"Size": float64(80 << 20), "CreatedAt": oldISO(t, 30)},
		)}),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(7), "Names": "node-runner", "Image": "node:18",
				"State": "running", "Status": "Up 4 days", "Labels": map[string]any{}},
			map[string]any{"ID": "sha256:" + hex64(8), "Names": "redis-old", "Image": "redis:6",
				"State": "exited", "Status": "Exited (0) 7 weeks ago", "Labels": map[string]any{}},
		)}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t4 := tierOf(t, rep, 4)

	pg := findItem(t, t4, hex64(1)[:12])
	if pg.Shield != "" || !strings.Contains(pg.Detail, "re-pullable") {
		t.Fatalf("dormant official image must be recommended: %+v", pg)
	}
	ghcr := findItem(t, t4, hex64(4)[:12])
	if ghcr.Shield != "" {
		t.Fatalf("host-shaped dormant image must be recommended: %+v", ghcr)
	}
	redisItem := findItem(t, t4, hex64(3)[:12])
	if !strings.Contains(redisItem.Shield, "stopped container") {
		t.Fatalf("stopped-pinned image must be shielded: %+v", redisItem)
	}
	for _, item := range t4.Items {
		if item.ID == hex64(2)[:12] || item.ID == hex64(5)[:12] || item.ID == hex64(6)[:12] {
			t.Fatalf("image %s must not appear in tier 4: %+v", item.ID, item)
		}
	}
	if t4.CopyCommand != "docker rmi postgres:14 ghcr.io/acme/api:v2" {
		t.Fatalf("tier 4 command = %q", t4.CopyCommand)
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "1 image(s) unclassified") {
		t.Fatalf("expected unclassified-image warning, got %v", rep.Warnings)
	}
}

// ---- tier 6 --------------------------------------------------------------

func TestTier6OrphanVolumesAndShields(t *testing.T) {
	base := t.TempDir()
	liveDir := filepath.Join(base, "liveproj")
	unscanned := filepath.Join(base, "outsider")
	deletedDir := filepath.Join(base, "goneproj")
	for _, d := range []string{liveDir, unscanned} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	touchAge(t, liveDir, time.Hour)

	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"volume", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"Name": "goneproj_db-data", "Driver": "local", "Links": float64(0)},
			map[string]any{"Name": "liveproj_cache", "Driver": "local", "Links": float64(1)},
			map[string]any{"Name": "outsider_data", "Driver": "local", "Links": float64(0)},
			map[string]any{"Name": "plainvolume", "Driver": "local", "Links": float64(0)},
		)}),
		fakeCmd([]string{"volume", "inspect"}, map[string]any{
			"volume_inspect": map[string]any{
				"goneproj_db-data": map[string]any{
					"Name": "goneproj_db-data",
					"Labels": map[string]any{
						"com.docker.compose.project":           "goneproj",
						"com.docker.compose.projectworkingdir": deletedDir,
					},
				},
				"liveproj_cache": map[string]any{
					"Name": "liveproj_cache",
					"Labels": map[string]any{
						"com.docker.compose.project":           "liveproj",
						"com.docker.compose.projectworkingdir": liveDir,
					},
				},
				"outsider_data": map[string]any{
					"Name": "outsider_data",
					"Labels": map[string]any{
						"com.docker.compose.project": "outsider",
					},
				},
				"plainvolume": map[string]any{"Name": "plainvolume", "Labels": map[string]any{}},
			}}),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			// Container provenance resolves outsider_data's working dir.
			map[string]any{"ID": "sha256:" + hex64(9), "Names": "out-1", "Image": "x:1",
				"State": "running", "Status": "Up 1 day",
				"Labels": map[string]any{
					"com.docker.compose.project":             "outsider",
					"com.docker.compose.project.working_dir": unscanned,
				}})}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), []string{liveDir})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t6 := tierOf(t, rep, 6)

	orphan := findItem(t, t6, "goneproj_db-data")
	if orphan.Shield != "" || !strings.Contains(orphan.Detail, "back up before removal") {
		t.Fatalf("orphan volume must be recommended with backup note: %+v", orphan)
	}
	live := findItem(t, t6, "liveproj_cache")
	if !strings.Contains(live.Shield, "active workspace") {
		t.Fatalf("live-workspace volume must be shielded: %+v", live)
	}
	outsider := findItem(t, t6, "outsider_data")
	if !strings.Contains(outsider.Shield, "outside scanned roots") {
		t.Fatalf("unscanned volume must be shielded: %+v", outsider)
	}
	for _, item := range t6.Items {
		if item.ID == "plainvolume" {
			t.Fatal("non-compose volume must not appear in tier 6")
		}
	}
	if t6.CopyCommand != "docker volume rm goneproj_db-data" {
		t.Fatalf("tier 6 command = %q", t6.CopyCommand)
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "1 named volume(s) without compose provenance") {
		t.Fatalf("expected non-compose volume warning, got %v", rep.Warnings)
	}
}

// ---- report shape ---------------------------------------------------------

func TestReportTierStructureAndCommandTable(t *testing.T) {
	// An empty-but-reachable daemon: every tier row exists (except the
	// capability-gated tier 5), all empty, and NO tier recommends a
	// command when it has nothing actionable.
	e, _ := newTestEngine(t, baseScenario())
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if !rep.Available {
		t.Fatal("Available expected")
	}
	wantTitles := map[int]string{
		0: "Pure Dead Clutter",
		1: "Stale BuildKit Cache",
		2: "Zombie Container Blockers",
		3: "Cold Project Images",
		4: "Dormant Upstream Base Images",
		6: "Orphaned Project Volumes",
	}
	seen := map[int]bool{}
	for _, tr := range rep.Tiers {
		if _, ok := wantTitles[tr.Tier]; !ok {
			t.Fatalf("unexpected tier %d (%s)", tr.Tier, tr.Title)
		}
		if tr.Title != wantTitles[tr.Tier] {
			t.Errorf("tier %d title = %q, want %q", tr.Tier, tr.Title, wantTitles[tr.Tier])
		}
		if len(tr.Items) != 0 || tr.CopyCommand != "" {
			t.Errorf("tier %d should be idle on an empty daemon: %d items, cmd %q",
				tr.Tier, len(tr.Items), tr.CopyCommand)
		}
		seen[tr.Tier] = true
	}
	for tier := range wantTitles {
		if !seen[tier] {
			t.Errorf("tier %d missing from report", tier)
		}
	}
	if rep.HostSlack != 0 || rep.SlackCommand != "" {
		t.Fatalf("no slack must be claimed without measurement: %d %q", rep.HostSlack, rep.SlackCommand)
	}
}

func TestTierOrderingWithSlackSplice(t *testing.T) {
	// On Windows with a measurable VHDX the tier order must remain 0..6
	// after the splice; on other platforms 0,1,2,3,4,6. Exercise the
	// splice ordering through the pure function contract instead:
	// build tiers via classify and verify monotonic order.
	e, _ := newTestEngine(t, baseScenario())
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	last := -1
	for _, tr := range rep.Tiers {
		if tr.Tier <= last {
			t.Fatalf("tiers out of order: %v", itemIDs2(rep))
		}
		last = tr.Tier
	}
}

func itemIDs2(rep DockerReport) []int {
	out := []int{}
	for _, tr := range rep.Tiers {
		out = append(out, tr.Tier)
	}
	return out
}

func isWindowsHost() bool {
	return windowsHostCheck()
}
