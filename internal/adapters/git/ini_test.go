package gitadapter

import (
	"reflect"
	"testing"
)

// .gitmodules is parsed by the pure-Go INI reader: submodule names only,
// comments ignored, quoted subsections unescaped, junk skipped.

func TestParseGitmodulesINI(t *testing.T) {
	data := []byte(`; comment
[submodule "child"]
	path = child
	url = https://example.com/child.git

# another comment
[submodule "with space"]
	path = sub dir
	url = https://example.com/ws.git

[submodule "escaped \"quote\" and \\ backslash"]
	path = esc

[core]
	something = else

[submodule]
	path = bare-section-no-name
`)
	got := parseGitmodulesINI(data)
	want := []string{"child", "with space", `escaped "quote" and \ backslash`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseGitmodulesINI = %q, want %q", got, want)
	}
}

func TestParseGitmodulesINIMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("random text\nno sections\n"),
		[]byte("[submodule \"unterminated\n"), // missing closing quote
		[]byte("[submodule ]\n"),              // empty name
	}
	for _, data := range cases {
		if got := parseGitmodulesINI(data); len(got) != 0 {
			t.Errorf("parseGitmodulesINI(%q) = %q, want none", data, got)
		}
	}
}
