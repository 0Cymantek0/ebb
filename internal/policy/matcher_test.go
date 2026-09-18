package policy

import (
	"strings"
	"testing"
)

// TestValidateRelPath covers the root-relative path contract.
func TestValidateRelPath(t *testing.T) {
	tests := []struct {
		path     string
		allowDot bool
		ok       bool
		why      string // substring of the error when !ok
	}{
		{"a/b/c.js", false, true, ""},
		{"node_modules/.pnpm/x", false, true, ""},
		{"a*b", false, true, ""}, // metacharacters are legal in literals
		{"*.env", false, true, ""},
		{"", false, false, "empty"},
		{"/abs/path", false, false, "absolute"},
		{"C:secrets", false, false, "drive"},
		{"C:/Users", false, false, "drive"},
		{"a/B:c", false, false, "drive"},
		{"a\\b", false, false, "backslash"},
		{"..", false, false, "'..'"},
		{"a/../b", false, false, "'..'"},
		{"a/..", false, false, "'..'"},
		{"a//b", false, false, "empty segment"},
		{"a/", false, false, "empty segment"},
		{"/", false, false, "absolute"},
		{"a/./b", false, false, "'.' segment"},
		{"a\u0000b", false, false, "NUL"},
		{".", true, true, ""},
		{".", false, false, "'.' segment"},
		{"./a", true, false, "'.' segment"},
	}
	for _, tt := range tests {
		err := ValidateRelPath(tt.path, tt.allowDot)
		if tt.ok != (err == nil) {
			t.Fatalf("ValidateRelPath(%q, %v) = %v, want ok=%v", tt.path, tt.allowDot, err, tt.ok)
		}
		if err != nil && tt.why != "" && !strings.Contains(err.Error(), tt.why) {
			t.Fatalf("error %q missing %q", err.Error(), tt.why)
		}
	}
}

// TestValidateGlob covers the restricted glob grammar.
func TestValidateGlob(t *testing.T) {
	tests := []struct {
		glob string
		ok   bool
		why  string
	}{
		{"a/b.js", true, ""},
		{"*.env", true, ""},
		{"?.log", true, ""},
		{"**", true, ""},
		{"a/**", true, ""},
		{"a/**/b", true, ""},
		{"**/b", true, ""},
		{"a**b", false, "complete path segment"},
		{"a/b**", false, "complete path segment"},
		{"a/**b", false, "complete path segment"},
		{"[ab].js", false, "unsupported syntax"},
		{"a/{b,c}.js", false, "unsupported syntax"},
		{"a/b[0-9].js", false, "unsupported syntax"},
		{"/abs/**", false, "absolute"},
		{"a\\*.js", false, "backslash"},
		{"../**", false, "'..'"},
		{"a/**/*", true, ""},
		{"a//**", false, "empty segment"},
		{"", false, "empty"},
	}
	for _, tt := range tests {
		err := ValidateGlob(tt.glob)
		if tt.ok != (err == nil) {
			t.Fatalf("ValidateGlob(%q) = %v, want ok=%v", tt.glob, err, tt.ok)
		}
		if err != nil && tt.why != "" && !strings.Contains(err.Error(), tt.why) {
			t.Fatalf("error %q missing %q", err.Error(), tt.why)
		}
	}
}

// TestGlobMatching pins the '**' complete-segment semantics: '**'
// matches zero or more whole segments; '*' and '?' never cross '/' and
// never match literal metacharacters.
func TestGlobMatching(t *testing.T) {
	tests := []struct {
		glob string
		path string
		want bool
	}{
		{"a/**", "a", true},             // ** covers zero segments
		{"a/**", "a/b", true},           //
		{"a/**", "a/b/c/d.txt", true},   //
		{"a/**", "ab", false},           // '*' does not cross the segment
		{"**", "anything/at/all", true}, //
		{"**", "x", true},               //
		{"a/**/b", "a/b", true},         // zero middle segments
		{"a/**/b", "a/x/y/b", true},     //
		{"a/**/b", "a/x/b/c", false},    // 'b' must be the last segment
		{"*.env", "x.env", true},        //
		{"*.env", "a/x.env", false},     // anchored at the declared root
		{"*.env", "*.env", false},       // F52: '*' never matches a literal '*'
		{"a?b", "axb", true},            //
		{"a?b", "a?b", false},           // F52: '?' never matches a literal '?'
		{"a*b", "axxb", true},           //
		{"a*b", "a/b", false},           // '*' stays inside one segment
		{"a*b", "a*b", false},           // F52
		{"a*b", "ab", true},             // '*' may match nothing
		{"**/*.ts", "x.ts", true},       //
		{"**/*.ts", "a/b/x.ts", true},   //
		{"A*", "abc", false},            // case-sensitive (conservative)
		{"a*", "ABC", false},            //
		{"certificates/**", "certificates/k1.pem", true},
	}
	for _, tt := range tests {
		if err := ValidateGlob(tt.glob); err != nil {
			t.Fatalf("test bug: glob %q invalid: %v", tt.glob, err)
		}
		got, err := matchGlobPath(tt.glob, tt.path)
		if err != nil {
			t.Errorf("MatchGlob(%q, %q): %v", tt.glob, tt.path, err)
			continue
		}
		if got != tt.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.glob, tt.path, got, tt.want)
		}
	}
}

// TestMatcherLiteralVsGlob verifies the two mechanisms are
// distinguishable and that literal paths are exact (F52): a file
// literally named "*.env" matches via [[sensitive]] paths but never via
// the pattern "*.env".
func TestMatcherLiteralVsGlob(t *testing.T) {
	m, err := NewMatcher([]Pattern{
		{Kind: PatternLiteral, Value: "*.env", Source: "sensitive[0].paths[0]"},
		{Kind: PatternGlob, Value: "*.env", Source: "sensitive[0].patterns[0]"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	r, err := m.Match("*.env")
	if err != nil {
		t.Fatalf("Match literal: %v", err)
	}
	if !r.Matched || r.Kind != MatchLiteral || r.Source != "sensitive[0].paths[0]" {
		t.Fatalf("literal match wrong: %+v", r)
	}

	r, err = m.Match("prod.env")
	if err != nil {
		t.Fatalf("Match glob: %v", err)
	}
	if !r.Matched || r.Kind != MatchGlob || r.Source != "sensitive[0].patterns[0]" {
		t.Fatalf("glob match wrong: %+v", r)
	}

	r, err = m.Match("other.txt")
	if err != nil {
		t.Fatalf("Match none: %v", err)
	}
	if r.Matched || r.Kind != MatchNone {
		t.Fatalf("non-match wrong: %+v", r)
	}
}

// TestMatcherInvalidPathErrors verifies malformed paths produce errors,
// not silent non-matches.
func TestMatcherInvalidPathErrors(t *testing.T) {
	m, err := NewMatcher([]Pattern{{Kind: PatternGlob, Value: "a/**", Source: "s"}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	for _, p := range []string{"", "/abs", "a\\b", "a/../b", "a\u0000"} {
		if _, err := m.Match(p); err == nil {
			t.Errorf("Match(%q) accepted an invalid path", p)
		}
	}
}

// TestMatcherInvalidPatternRejected covers constructor validation.
func TestMatcherInvalidPatternRejected(t *testing.T) {
	if _, err := NewMatcher([]Pattern{{Kind: PatternGlob, Value: "a**b", Source: "s"}}); err == nil {
		t.Error("invalid glob accepted")
	}
	if _, err := NewMatcher([]Pattern{{Kind: PatternLiteral, Value: "/abs", Source: "s"}}); err == nil {
		t.Error("invalid literal accepted")
	}
	if _, err := NewMatcher([]Pattern{{Kind: PatternKind("regex"), Value: "a", Source: "s"}}); err == nil {
		t.Error("unknown pattern kind accepted")
	}
}

// POL-GLOB-1: hostile patterns must fail fast with an error, not hang
// the backtracking matcher.
func TestGlobBudgetRejectsPathologicalPattern(t *testing.T) {
	pattern := "*a*a*a*a*a*a*a*a*a*b"
	if err := ValidateGlob(pattern); err != nil {
		t.Skipf("pattern rejected at validation: %v", err)
	}
	m, err := NewMatcher([]Pattern{{Kind: PatternGlob, Value: pattern, Source: "t"}})
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for i := 0; i < 60; i++ {
		name += "a"
	}
	if _, err := m.Match(name); err == nil {
		t.Fatalf("expected budget error for pathological pattern %q against %d chars", pattern, len(name))
	}
}
