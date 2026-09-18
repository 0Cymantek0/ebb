package gitadapter

import (
	"reflect"
	"strings"
	"testing"
)

// Pass 1 parses the merged config view: execution keys are collected for
// empty override, command-scope entries (the adapter's own -c flags) are
// excluded, and lookups use git's case-insensitive key semantics.

func TestParseConfigListCollectsExecutionKeys(t *testing.T) {
	out := strings.Join([]string{
		"system\tfile:C:/Program Files/Git/etc/gitconfig\tfilter.lfs.clean=git-lfs clean -- %f",
		"local\tfile:.git/config\tfilter.evil.clean=touch /evil",
		"local\tfile:.git/config\tFilter.EVIL.CLEAN=touch /evil2", // case-mangled section/variable
		"local\tfile:.git/config\tfilter.evil.smudge=touch /evil",
		"local\tfile:.git/config\tfilter.lfs.process=git-lfs filter-process",
		"local\tfile:.git/config\tdiff.evil.textconv=touch /evil",
		"local\tfile:.git/config\tdiff.mytool.command=touch /evil",
		"local\tfile:.git/config\tdiff.external=touch /evil",  // statically covered
		"local\tfile:.git/config\tcore.fsmonitor=touch /evil", // statically covered
		"local\tfile:.git/config\tcore.pager=touch /evil",
		"local\tfile:.git/config\tcore.editor=touch /evil",
		"local\tfile:.git/config\tcore.bare=false",     // not execution-capable
		"local\tfile:.git/config\tuser.name=A",         // not execution-capable
		"command\tcommand line:\tcore.fsmonitor=false", // adapter's own flag: excluded
		"include\tfile:/evil/inc.conf\talias.from-include=!touch /evil",
		"local\tfile:.git/config\tremote.origin.promisor=true",
		"local\tfile:.git/config\tremote.origin.partialclonefilter=blob:none",
		"local\tfile:.git/config\textensions.objectformat=sha256",
		"local\tfile:.git/config\turl.git@example.com:.insteadOf=https://example.com/",
		"malformed line without tabs or equals",
	}, "\n")
	inv := parseConfigList(out)

	want := []string{
		"filter.lfs.clean", // any scope; dedup keeps the first spelling of a key
		"filter.evil.clean",
		"filter.evil.smudge",
		"filter.lfs.process",
		"diff.evil.textconv",
		"diff.mytool.command",
		"core.pager",
		"core.editor",
	}
	if !reflect.DeepEqual(inv.overrideKeys, want) {
		t.Errorf("overrideKeys = %v, want %v", inv.overrideKeys, want)
	}
	argv := inv.overrideArgs()
	if len(argv) != 2*len(want) {
		t.Fatalf("overrideArgs len = %d, want %d", len(argv), 2*len(want))
	}
	for i := 0; i < len(argv); i += 2 {
		if argv[i] != "-c" || !strings.HasSuffix(argv[i+1], "=") {
			t.Errorf("override pair %q %q, want -c key=", argv[i], argv[i+1])
		}
	}
	if !inv.isPartialClone() {
		t.Error("isPartialClone = false, want true (promisor=true)")
	}
	if inv.values["extensions.objectformat"] != "sha256" {
		t.Errorf("objectformat lookup = %q", inv.values["extensions.objectformat"])
	}
	if !inv.hasPrefixKey("filter.lfs.") {
		t.Error("filter.lfs. prefix not detected")
	}
}

func TestParseConfigListNoExecutionKeys(t *testing.T) {
	inv := parseConfigList("local\tfile:.git/config\tcore.bare=false\n")
	if len(inv.overrideKeys) != 0 {
		t.Errorf("overrideKeys = %v, want none", inv.overrideKeys)
	}
	if inv.isPartialClone() {
		t.Error("isPartialClone = true, want false")
	}
	if inv.overrideArgs() != nil {
		t.Errorf("overrideArgs = %v, want nil", inv.overrideArgs())
	}
}

func TestIsPartialCloneVariants(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"local\tf\tremote.origin.promisor=true\n", true},
		{"local\tf\tremote.origin.promisor=TRUE\n", true},
		{"local\tf\tremote.origin.promisor=false\n", false},
		{"local\tf\tremote.origin.partialclonefilter=blob:none\n", true},
		{"local\tf\tremote.origin.partialclonefilter=\n", false},
		{"local\tf\tremote.origin.url=https://x\n", false},
	}
	for _, c := range cases {
		if got := parseConfigList(c.out).isPartialClone(); got != c.want {
			t.Errorf("isPartialClone(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}

func TestExecutionKeyCaseSemantics(t *testing.T) {
	yes := []string{
		"filter.x.clean", "Filter.x.CLEAN", "filter.a.b.clean", // dotted subsection
		"filter.x.smudge", "FILTER.x.Smudge", "filter.x.process",
		"diff.x.textconv", "Diff.X.TextConv", "diff.x.command",
		"core.pager", "Core.PAGER", "core.editor",
		"diff.external", "core.fsmonitor",
	}
	no := []string{
		"filter.x.required", "filter.lfs", "filter.cleandrive.x",
		"diff.colormoved", "diff.externalx", "corex.pager",
		"core.pagerx", "alias.status", "user.name",
	}
	for _, k := range yes {
		if !executionKey(k) {
			t.Errorf("executionKey(%q) = false, want true", k)
		}
	}
	for _, k := range no {
		if executionKey(k) {
			t.Errorf("executionKey(%q) = true, want false", k)
		}
	}
}
