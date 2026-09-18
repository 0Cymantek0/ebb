package gitadapter

import (
	"reflect"
	"testing"

	"ebb/internal/domain"
)

func TestParsePorcelainV2Counts(t *testing.T) {
	out := `# branch.oid ade1d48da1d72d1e7a3a07008da6c7cc026212a
# branch.head main
# branch.upstream origin/main
# branch.ab +0 -0
1 .M N... 100644 100644 100644 123 456 789012 keep.txt
1 A. N... 000000 100644 100644 000 456 000000 staged.txt
2 R. N... 100644 100644 100644 123 456 789012 renamed.txt	orig.txt
u UU N... 100644 100644 100644 100644 111 222 333 base.txt
? untracked-dir/
`
	c := parsePorcelainV2(out)
	if c.unmerged != 1 {
		t.Errorf("unmerged = %d, want 1", c.unmerged)
	}
	if c.untracked != 1 {
		t.Errorf("untracked = %d, want 1", c.untracked)
	}
	if c.changed != 3 {
		t.Errorf("changed = %d, want 3", c.changed)
	}
	if !c.dirty {
		t.Error("dirty = false, want true")
	}
	if c := parsePorcelainV2("# branch.head main\n"); c.dirty || c.unmerged != 0 || c.untracked != 0 {
		t.Errorf("branch-only porcelain gave %+v", c)
	}
	if c := parsePorcelainV2(""); c.dirty {
		t.Error("empty output counted dirty")
	}
}

func TestParseRemoteV(t *testing.T) {
	out := "origin\thttps://example.com/proj.git (fetch)\n" +
		"origin\tgit@example.com:proj.git (push)\n" +
		"upstream\thttps://example.com/up.git (fetch)\n" +
		"upstream\thttps://example.com/up.git (push)\n"
	want := []domain.GitRemote{
		{Name: "origin", URL: "https://example.com/proj.git", Push: "git@example.com:proj.git"},
		{Name: "upstream", URL: "https://example.com/up.git", Push: "https://example.com/up.git"},
	}
	got := parseRemoteV(out)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRemoteV = %+v, want %+v", got, want)
	}
	if parseRemoteV("") != nil {
		t.Error("parseRemoteV(empty) != nil")
	}
	// Malformed lines are skipped, not trusted.
	if r := parseRemoteV("garbage without tabs\nnope\tmissing-suffix\n"); r != nil {
		t.Errorf("parseRemoteV(malformed) = %+v, want nil", r)
	}
}

func TestParseWorktreePorcelain(t *testing.T) {
	out := `worktree C:/Users/x/wtparent
HEAD 815ae2d4e056904100469146bdd878d489f472bf
branch refs/heads/main

worktree C:/Users/x/wt-leaf
HEAD 9999999999999999999999999999999999999999
branch refs/heads/leaf
locked reason text here

worktree C:/Users/x/wt-det
HEAD 7777777777777777777777777777777777777777
detached

`
	got := parseWorktreePorcelain(out)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (main + 2 linked): %+v", len(got), got)
	}
	if got[0].Path != "C:/Users/x/wtparent" || got[0].Branch != "refs/heads/main" || got[0].Bare {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[1].Branch != "refs/heads/leaf" || got[1].Head != "9999999999999999999999999999999999999999" {
		t.Errorf("entry 1 = %+v", got[1])
	}
	if !got[2].Detached || got[2].Branch != "" {
		t.Errorf("entry 2 = %+v, want detached", got[2])
	}

	bare := "worktree C:/repos/x.git\nHEAD 1111111111111111111111111111111111111111\nbare\n\n"
	got = parseWorktreePorcelain(bare)
	if len(got) != 1 || !got[0].Bare {
		t.Errorf("bare entry = %+v", got)
	}
}
