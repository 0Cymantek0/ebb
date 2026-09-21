package cli

// Wave 2 wiring tests: the production RealDeps seams behind `ebb
// analyse` — the git survey adapter (field-for-field conversion) and the
// docker engine adapter (honest degradation without a daemon).

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestRealDepsGitSurveyWiring(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git binary absent: %v", err)
	}
	deps := RealDeps()
	if deps.AnalyseGitSurvey == nil {
		t.Fatal("RealDeps left AnalyseGitSurvey nil")
	}
	root := t.TempDir()
	runGit(t, root, "init", "-q")
	runGit(t, root, "commit", "--allow-empty", "-q", "-m", "x", "--date=@1700000000")
	rs, err := deps.AnalyseGitSurvey.SurveyRepo(context.Background(), root)
	if err != nil {
		t.Fatalf("SurveyRepo: %v", err)
	}
	if !rs.IsRepo || rs.HeadCommit == "" {
		t.Fatalf("wired survey returned %+v", rs)
	}
	// The author-date wiring round-trips through the conversion adapter.
	if rs.LastActivityAt.Before(time.Unix(1699999000, 0)) {
		t.Fatalf("LastActivityAt = %v, expected the pinned commit date", rs.LastActivityAt)
	}
	if rs.UnpushedCommits == 0 {
		t.Fatalf("no-upstream repo must report -1 unpushed, got %d", rs.UnpushedCommits)
	}
}

func TestRealDepsDockerEngineWiring(t *testing.T) {
	deps := RealDeps()
	if _, err := exec.LookPath("docker"); err != nil {
		if deps.AnalyseDocker != nil {
			t.Fatal("docker engine wired without a docker binary on PATH")
		}
		t.Skipf("docker binary absent (nil seam is the honest wiring): %v", err)
	}
	if deps.AnalyseDocker == nil {
		t.Fatal("docker binary present but AnalyseDocker left nil")
	}
	// Report must degrade (never panic, never error) when the daemon is
	// down; when the daemon is up it must at least produce a report.
	rep, err := deps.AnalyseDocker.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report errored: %v", err)
	}
	if !rep.Available {
		if len(rep.Warnings) == 0 {
			t.Fatalf("unavailable report carries no warning: %+v", rep)
		}
	}
}
