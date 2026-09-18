package policy

import (
	"fmt"
)

// PatternKind distinguishes the two matching mechanisms of v1.
type PatternKind string

// The v1 matching mechanisms.
const (
	// PatternLiteral matches exactly one path spelling.
	PatternLiteral PatternKind = "literal"
	// PatternGlob matches via the restricted glob grammar.
	PatternGlob PatternKind = "glob"
)

// MatchKind reports which mechanism produced a match ("none" when the
// path did not match).
type MatchKind string

// The v1 match mechanisms.
const (
	MatchNone    MatchKind = "none"
	MatchLiteral MatchKind = "literal"
	MatchGlob    MatchKind = "glob"
)

// Pattern is one matching rule before compilation.
type Pattern struct {
	Kind   PatternKind
	Value  string
	Source string // human-stable rule identifier, e.g. "preserve[0].patterns[1]"
}

// MatchResult is the outcome of matching one path against a Matcher.
// When Matched is false, Kind is MatchNone and Source/Value are empty.
type MatchResult struct {
	Matched bool
	Kind    MatchKind
	Source  string
	Value   string
}

// Matcher holds compiled policy patterns and matches root-relative paths
// against them. Literal matches take precedence over glob matches, and
// within a kind earlier-declared patterns win, so results are
// deterministic in declaration order.
type Matcher struct {
	literals map[string]string // path -> source of first declaration
	globs    []Pattern
}

// NewMatcher compiles patterns, validating every value with the strict
// path/glob rules. It returns an error naming the first invalid pattern;
// it never panics on malformed input.
func NewMatcher(patterns []Pattern) (*Matcher, error) {
	m := &Matcher{literals: make(map[string]string, len(patterns))}
	for _, p := range patterns {
		switch p.Kind {
		case PatternLiteral:
			if err := ValidateRelPath(p.Value, false); err != nil {
				return nil, fmt.Errorf("literal %q (%s): %w", p.Value, p.Source, err)
			}
			if _, exists := m.literals[p.Value]; !exists {
				m.literals[p.Value] = p.Source
			}
		case PatternGlob:
			if err := ValidateGlob(p.Value); err != nil {
				return nil, fmt.Errorf("glob %q (%s): %w", p.Value, p.Source, err)
			}
			m.globs = append(m.globs, p)
		default:
			return nil, fmt.Errorf("pattern %q (%s): unknown pattern kind %q", p.Value, p.Source, p.Kind)
		}
	}
	return m, nil
}

// Match reports how path matched. An invalid path (failed root-relative
// validation) returns an error rather than a silent non-match.
func (m *Matcher) Match(path string) (MatchResult, error) {
	if err := ValidateRelPath(path, false); err != nil {
		return MatchResult{}, err
	}
	if src, ok := m.literals[path]; ok {
		return MatchResult{Matched: true, Kind: MatchLiteral, Source: src, Value: path}, nil
	}
	for _, g := range m.globs {
		ok, err := matchGlobPath(g.Value, path)
		if err != nil {
			return MatchResult{}, err
		}
		if ok {
			return MatchResult{Matched: true, Kind: MatchGlob, Source: g.Source, Value: g.Value}, nil
		}
	}
	return MatchResult{Kind: MatchNone}, nil
}

// PreserveMatcher compiles every [[preserve]] pattern (globs only in
// v1).
func (p Policy) PreserveMatcher() (*Matcher, error) {
	ps := make([]Pattern, 0, len(p.Preserve))
	for i, pr := range p.Preserve {
		for j, v := range pr.Patterns {
			ps = append(ps, Pattern{Kind: PatternGlob, Value: v,
				Source: fmt.Sprintf("preserve[%d].patterns[%d]", i, j)})
		}
	}
	return NewMatcher(ps)
}

// SensitiveMatcher compiles [[sensitive]] literal paths and globs into
// one matcher. Sources distinguish the two mechanisms.
func (p Policy) SensitiveMatcher() (*Matcher, error) {
	var ps []Pattern
	for i, s := range p.Sensitive {
		for j, v := range s.Paths {
			ps = append(ps, Pattern{Kind: PatternLiteral, Value: v,
				Source: fmt.Sprintf("sensitive[%d].paths[%d]", i, j)})
		}
		for j, v := range s.Patterns {
			ps = append(ps, Pattern{Kind: PatternGlob, Value: v,
				Source: fmt.Sprintf("sensitive[%d].patterns[%d]", i, j)})
		}
	}
	return NewMatcher(ps)
}

// OutputMatcher compiles every regenerate output as a literal path. It
// answers "is this path a declared output root", not "is it inside one"
// — use Resolve for containment semantics.
func (p Policy) OutputMatcher() (*Matcher, error) {
	var ps []Pattern
	for _, g := range p.Regenerate {
		for j, v := range g.Outputs {
			ps = append(ps, Pattern{Kind: PatternLiteral, Value: v,
				Source: fmt.Sprintf("regenerate[%s].outputs[%d]", g.ID, j)})
		}
	}
	return NewMatcher(ps)
}
