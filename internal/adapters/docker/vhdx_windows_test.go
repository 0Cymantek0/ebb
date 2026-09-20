//go:build windows

package dockeradapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAlloc is an injected AllocationProbe with canned sizes.
type fakeAlloc struct {
	sizes map[string]int64
}

func (f fakeAlloc) AllocatedSize(path string) (int64, bool) {
	n, ok := f.sizes[path]
	return n, ok
}

// setupVHDX creates a fake %LOCALAPPDATA%\Docker\wsl\data\ext4.vhdx and
// returns its path.
func setupVHDX(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	vhdx := filepath.Join(base, "Docker", "wsl", "data", "ext4.vhdx")
	if err := os.MkdirAll(filepath.Dir(vhdx), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vhdx, []byte("sparse-ish payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return vhdx
}

func dfScenario(t *testing.T, logical int64) map[string]any {
	t.Helper()
	return mergeScenario(baseScenario(),
		fakeCmd([]string{"system", "df"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"Type": "Images", "Size": float64(logical)})}),
	)
}

func TestHostSlackMeasuredAboveThreshold(t *testing.T) {
	vhdx := setupVHDX(t)
	scenario := dfScenario(t, 10<<30)
	fe := startFake(t, scenario)
	e := NewWithAllocationProbe(fe.exe, fakeAlloc{sizes: map[string]int64{vhdx: 40 << 30}})
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.HostSlack != 30<<30 {
		t.Fatalf("HostSlack = %d, want %d", rep.HostSlack, 30<<30)
	}
	if rep.SlackCommand != cmdHostSlack {
		t.Fatalf("SlackCommand = %q, want %q", rep.SlackCommand, cmdHostSlack)
	}
	t5 := tierOf(t, rep, 5)
	if len(t5.Items) != 1 || !strings.Contains(t5.Items[0].Detail, "reclaimable") {
		t.Fatalf("tier 5 items = %+v", t5.Items)
	}
	if !strings.Contains(t5.CopyCommand, "wsl --manage docker-desktop --set-sparse true") ||
		!strings.Contains(t5.CopyCommand, "fstrim -v /") {
		t.Fatalf("tier 5 command must be the plan's WSL compaction sequence: %q", t5.CopyCommand)
	}
	// Tier order stays 0..6 with the splice.
	for i, tr := range rep.Tiers {
		if tr.Tier != i {
			t.Fatalf("tier order broken at %d: %+v", i, rep.Tiers)
		}
	}
}

func TestHostSlackBelowThresholdNoAdvice(t *testing.T) {
	vhdx := setupVHDX(t)
	scenario := dfScenario(t, 10<<30)
	fe := startFake(t, scenario)
	e := NewWithAllocationProbe(fe.exe, fakeAlloc{sizes: map[string]int64{vhdx: 12 << 30}})
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.HostSlack != 2<<30 {
		t.Fatalf("HostSlack = %d, want %d", rep.HostSlack, 2<<30)
	}
	if rep.SlackCommand != "" {
		t.Fatalf("no compaction advice below the 5 GiB threshold: %q", rep.SlackCommand)
	}
	for _, tr := range rep.Tiers {
		if tr.Tier == TierHostVHDXSlack {
			t.Fatal("tier 5 row must not appear below the threshold")
		}
	}
}

func TestHostSlackNegativeClamped(t *testing.T) {
	// Guest logical usage above physical (compression): zero slack, no
	// advice — never a negative claim.
	vhdx := setupVHDX(t)
	scenario := dfScenario(t, 40<<30)
	fe := startFake(t, scenario)
	e := NewWithAllocationProbe(fe.exe, fakeAlloc{sizes: map[string]int64{vhdx: 10 << 30}})
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.HostSlack != 0 || rep.SlackCommand != "" {
		t.Fatalf("negative slack must clamp to zero: %d %q", rep.HostSlack, rep.SlackCommand)
	}
}

func TestHostSlackNoVHDXFound(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	e, fe := newTestEngineWithNativeProbe(t, baseScenario())
	_ = e
	_ = fe
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.HostSlack != 0 {
		t.Fatalf("HostSlack = %d, want 0", rep.HostSlack)
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "no Docker Desktop virtual disk found") {
		t.Fatalf("expected not-found warning, got %v", rep.Warnings)
	}
}

// newTestEngineWithNativeProbe keeps the native allocation probe
// (exercising the LOCALAPPDATA search) but still points the CLI at the
// fake.
func newTestEngineWithNativeProbe(t *testing.T, scenario map[string]any) (*Engine, *fakeEnv) {
	t.Helper()
	fe := startFake(t, scenario)
	return New(fe.exe), fe
}
