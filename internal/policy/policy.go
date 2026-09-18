// Package policy parses, validates and resolves Ebbfile.toml v1
// (Foundation §7).
//
// Strictness contract: every TOML decode in this package goes through
// strictDecode, which always enables pelletier/go-toml v2
// DisallowUnknownFields, so an unknown or misspelled field is always an
// error, never a silently ignored safety setting (D002, F52). Duplicate
// keys are rejected by the TOML parser itself.
//
// Paths are root-relative, use '/', and reject NUL bytes, absolute roots,
// drive prefixes (a single letter followed by ':'), '..' segments, '.'
// segments (the only exception: the regenerate root default "."), empty
// segments and backslashes (Foundation §7.2).
//
// Glob grammar is restricted to '*' (any run of characters within one
// segment), '?' (exactly one character within one segment) and '**' only
// as a complete path segment (zero or more segments). Any other
// regular-expression-like syntax ('[', ']', '{', '}') is rejected, as is
// '**' embedded inside a segment such as 'a**b'.
//
// Matching is case-sensitive everywhere in v1. This is the conservative
// direction: on a case-insensitive filesystem a pattern that fails to
// match a differently-cased name preserves the file instead of silently
// releasing it.
//
// Literal paths and globs are distinct mechanisms (F52): a literal path
// matches exactly one spelling, while a glob's '*' and '?' never match a
// literal '*' or '?' character in a filename. A file literally named
// "*.env" is therefore matched by [[sensitive]] paths, never by the
// pattern "*.env". [[preserve]] v1 offers globs only; a file whose name
// itself contains glob metacharacters can only be preserved through
// containment in a matched directory — a known v1 limitation.
//
// v1 policy can never produce domain.RouteDiscard: discard exists in the
// domain enum but no v1 schema field can express it, and Resolve refuses
// to invent one. Discard authority lives outside the policy file.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// NetworkPolicy is the top-level network posture of the workspace
// ([policy].network). v1 accepts exactly one value.
type NetworkPolicy string

// NetworkApprovedActions is the only accepted [policy].network in v1:
// network use requires an approved action.
const NetworkApprovedActions NetworkPolicy = "approved-actions"

// UnknownHandling is the treatment of unclassified content
// ([policy].unknown). v1 accepts exactly one value because it is an
// invariant, not a preference toggle.
type UnknownHandling string

// UnknownPreserve is the only accepted [policy].unknown in v1.
const UnknownPreserve UnknownHandling = "preserve"

// Adapter names a supported regeneration adapter ([[regenerate]].adapter).
type Adapter string

// Supported regeneration adapters in v1.
const (
	AdapterPNPM   Adapter = "pnpm"
	AdapterNPM    Adapter = "npm"
	AdapterUV     Adapter = "uv"
	AdapterPip    Adapter = "pip"
	AdapterCustom Adapter = "custom"
)

// GroupNetwork is the network declaration of one regenerate group.
type GroupNetwork string

// Accepted [[regenerate]].network values.
const (
	GroupNetworkAllowed          GroupNetwork = "allowed"
	GroupNetworkOfflineArtifacts GroupNetwork = "offline-artifacts"
)

// ExternalKind classifies an [[external]] binding.
type ExternalKind string

// Accepted [[external]].kind values.
const (
	ExternalDirectory ExternalKind = "directory"
	ExternalFile      ExternalKind = "file"
	ExternalService   ExternalKind = "service"
	ExternalVolume    ExternalKind = "volume"
)

// Policy is a parsed, validated Ebbfile.toml v1 document.
type Policy struct {
	Version    int          `toml:"version"`
	Workspace  Workspace    `toml:"workspace"`
	Rules      Rules        `toml:"policy"`
	Preserve   []Preserve   `toml:"preserve"`
	Sensitive  []Sensitive  `toml:"sensitive"`
	Regenerate []Regenerate `toml:"regenerate"`
	External   []External   `toml:"external"`
}

// Workspace names the declared development scope.
type Workspace struct {
	Name string `toml:"name"`
}

// Rules carries the top-level [policy] section.
type Rules struct {
	Network NetworkPolicy   `toml:"network"`
	Unknown UnknownHandling `toml:"unknown"`
}

// Preserve is one explicit preservation rule. Patterns are globs.
type Preserve struct {
	Patterns []string `toml:"patterns"`
	Reason   string   `toml:"reason"`
}

// Sensitive marks content whose storage, logging and export must be
// handled with care. Sensitivity never selects a route (Foundation §6.2).
// Paths are matched literally; patterns are globs.
type Sensitive struct {
	Paths    []string `toml:"paths"`
	Patterns []string `toml:"patterns"`
}

// Regenerate declares one rebuildable output group. Root, outputs and
// inputs are all root-relative to the workspace root; root additionally
// selects the action's working directory (outputs are NOT interpreted
// relative to it).
type Regenerate struct {
	ID      string       `toml:"id"`
	Adapter Adapter      `toml:"adapter"`
	Root    string       `toml:"root"`
	Outputs []string     `toml:"outputs"`
	Inputs  []string     `toml:"inputs"`
	Network GroupNetwork `toml:"network"`
	Command []string     `toml:"command"`
}

// External is one declared dependency outside the retained payload.
// Location is a local binding NAME, never a secret-bearing path.
type External struct {
	ID        string       `toml:"id"`
	Kind      ExternalKind `toml:"kind"`
	Location  string       `toml:"location"`
	Ownership string       `toml:"ownership"`
	Required  bool         `toml:"required"`
}

// Parse decodes and validates an Ebbfile.toml document. Unknown fields
// and duplicate keys are rejected by the decoder; semantic violations are
// rejected by Validate.
func Parse(data []byte) (Policy, error) {
	var p Policy
	if err := strictDecode(data, &p); err != nil {
		return Policy{}, err
	}
	// Decode-level default: regenerate root "." when omitted.
	for i := range p.Regenerate {
		if p.Regenerate[i].Root == "" {
			p.Regenerate[i].Root = "."
		}
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// ParseFile reads and parses the Ebbfile at path.
func ParseFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("Ebbfile: read %s: %w", path, err)
	}
	return Parse(data)
}

// strictDecode is the only TOML decoding path in this package. It always
// enables DisallowUnknownFields so strictness cannot be forgotten (D002),
// and it renders strict-missing errors with the offending key names so a
// misspelled safety field is named, not lumped into a generic failure.
func strictDecode(data []byte, v any) error {
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		return nil
	}
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		keys := make([]string, 0, len(strict.Errors))
		for _, de := range strict.Errors {
			keys = append(keys, strings.Join(de.Key(), "."))
		}
		return fmt.Errorf("Ebbfile: unknown field(s) %s rejected (v1 schema is strict; a misspelled safety key must error, not vanish)",
			strings.Join(keys, ", "))
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, _ := de.Position()
		return fmt.Errorf("Ebbfile: %w (line %d)", err, row)
	}
	return fmt.Errorf("Ebbfile: %w", err)
}

// Default returns the conservative no-Ebbfile policy (Foundation §7.1:
// with no file present, conservative defaults apply — everything
// preserved, nothing regenerable, no external bindings).
func Default(workspaceName string) Policy {
	if strings.TrimSpace(workspaceName) == "" {
		workspaceName = "workspace"
	}
	return Policy{
		Version:   1,
		Workspace: Workspace{Name: workspaceName},
		Rules:     Rules{Network: NetworkApprovedActions, Unknown: UnknownPreserve},
	}
}

// Validate enforces the v1 acceptance rules, returning errors that name
// the offending field.
func (p Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("Ebbfile: version: must be 1, got %d", p.Version)
	}
	if p.Workspace.Name == "" {
		return fmt.Errorf("Ebbfile: [workspace].name: required")
	}
	if p.Rules.Network != NetworkApprovedActions {
		return fmt.Errorf("Ebbfile: [policy].network: only %q is accepted in v1, got %q",
			NetworkApprovedActions, p.Rules.Network)
	}
	if p.Rules.Unknown != UnknownPreserve {
		return fmt.Errorf("Ebbfile: [policy].unknown: %q is an invariant, not a preference; only %q is accepted, got %q",
			"preserve", UnknownPreserve, p.Rules.Unknown)
	}

	for i, pr := range p.Preserve {
		if len(pr.Patterns) == 0 {
			return fmt.Errorf("Ebbfile: preserve[%d].patterns: at least one pattern is required", i)
		}
		if strings.TrimSpace(pr.Reason) == "" {
			return fmt.Errorf("Ebbfile: preserve[%d].reason: required (why these bytes are preserved)", i)
		}
		for j, pat := range pr.Patterns {
			if err := ValidateGlob(pat); err != nil {
				return fmt.Errorf("Ebbfile: preserve[%d].patterns[%d]: %w", i, j, err)
			}
		}
	}

	for i, s := range p.Sensitive {
		if len(s.Paths)+len(s.Patterns) == 0 {
			return fmt.Errorf("Ebbfile: sensitive[%d]: at least one path or pattern is required", i)
		}
		for j, path := range s.Paths {
			if err := ValidateRelPath(path, false); err != nil {
				return fmt.Errorf("Ebbfile: sensitive[%d].paths[%d]: %w", i, j, err)
			}
		}
		for j, pat := range s.Patterns {
			if err := ValidateGlob(pat); err != nil {
				return fmt.Errorf("Ebbfile: sensitive[%d].patterns[%d]: %w", i, j, err)
			}
		}
	}

	ids := make(map[string]bool, len(p.Regenerate))
	for i, g := range p.Regenerate {
		if g.ID == "" {
			return fmt.Errorf("Ebbfile: regenerate[%d].id: required", i)
		}
		if ids[g.ID] {
			return fmt.Errorf("Ebbfile: regenerate[%d].id: duplicate id %q", i, g.ID)
		}
		ids[g.ID] = true

		switch g.Adapter {
		case AdapterPNPM, AdapterNPM, AdapterUV, AdapterPip, AdapterCustom:
		default:
			return fmt.Errorf("Ebbfile: regenerate[%q].adapter: must be one of pnpm, npm, uv, pip, custom; got %q", g.ID, g.Adapter)
		}

		if g.Root == "" {
			return fmt.Errorf("Ebbfile: regenerate[%q].root: required (the \".\" default is applied by Parse)", g.ID)
		}
		if err := ValidateRelPath(g.Root, true); err != nil {
			return fmt.Errorf("Ebbfile: regenerate[%q].root: %w", g.ID, err)
		}

		if len(g.Outputs) == 0 {
			return fmt.Errorf("Ebbfile: regenerate[%q].outputs: at least one root-relative path is required", g.ID)
		}
		seenOut := make(map[string]bool, len(g.Outputs))
		for j, o := range g.Outputs {
			if err := ValidateRelPath(o, false); err != nil {
				return fmt.Errorf("Ebbfile: regenerate[%q].outputs[%d]: %w", g.ID, j, err)
			}
			if seenOut[o] {
				return fmt.Errorf("Ebbfile: regenerate[%q].outputs[%d]: duplicate output %q", g.ID, j, o)
			}
			seenOut[o] = true
		}

		if len(g.Inputs) == 0 {
			return fmt.Errorf("Ebbfile: regenerate[%q].inputs: at least one root-relative path is required", g.ID)
		}
		for j, in := range g.Inputs {
			if err := ValidateRelPath(in, false); err != nil {
				return fmt.Errorf("Ebbfile: regenerate[%q].inputs[%d]: %w", g.ID, j, err)
			}
		}

		switch g.Network {
		case GroupNetworkAllowed, GroupNetworkOfflineArtifacts:
		default:
			return fmt.Errorf("Ebbfile: regenerate[%q].network: must be \"allowed\" or \"offline-artifacts\", got %q", g.ID, g.Network)
		}

		if g.Adapter == AdapterCustom {
			if len(g.Command) == 0 {
				return fmt.Errorf("Ebbfile: regenerate[%q].command: required when adapter is \"custom\"", g.ID)
			}
			if g.Command[0] == "" {
				return fmt.Errorf("Ebbfile: regenerate[%q].command: first element (program) must not be empty", g.ID)
			}
		} else if len(g.Command) > 0 {
			return fmt.Errorf("Ebbfile: regenerate[%q].command: forbidden unless adapter is \"custom\" (got adapter %q)", g.ID, g.Adapter)
		}
	}

	extIDs := make(map[string]bool, len(p.External))
	for i, ex := range p.External {
		if ex.ID == "" {
			return fmt.Errorf("Ebbfile: external[%d].id: required", i)
		}
		if extIDs[ex.ID] {
			return fmt.Errorf("Ebbfile: external[%d].id: duplicate id %q", i, ex.ID)
		}
		extIDs[ex.ID] = true

		switch ex.Kind {
		case ExternalDirectory, ExternalFile, ExternalService, ExternalVolume:
		default:
			return fmt.Errorf("Ebbfile: external[%q].kind: must be one of directory, file, service, volume; got %q", ex.ID, ex.Kind)
		}

		if err := validateBindingName(ex.Location); err != nil {
			return fmt.Errorf("Ebbfile: external[%q].location: %w", ex.ID, err)
		}

		switch ex.Ownership {
		case "owned", "shared", "reference-only":
		default:
			return fmt.Errorf("Ebbfile: external[%q].ownership: must be one of owned, shared, reference-only; got %q", ex.ID, ex.Ownership)
		}
	}

	return nil
}

// validateBindingName checks that an [[external]] location is a local
// binding name, not a (secret-bearing) path.
func validateBindingName(name string) error {
	if name == "" {
		return fmt.Errorf("required")
	}
	if strings.ContainsAny(name, "\x00/\\:") {
		return fmt.Errorf("must be a local binding name, not a path (got %q)", name)
	}
	if name == ".." || name == "." || strings.Contains(name, "..") {
		return fmt.Errorf("must be a local binding name, not a path (got %q)", name)
	}
	return nil
}
