// Package ecosystem implements the v1 package-ecosystem adapters of
// Foundation §9.3-9.4: detection of regenerable dependency-tree groups
// from root-level package-manager markers, and generation of their
// recovery-action recipes (recipe.go).
//
// Detection is marker EXISTENCE only, at the workspace root — nested or
// namespaced workspaces are out of scope in v1. The package never reads
// file contents, never executes anything and never mutates the
// workspace; the only I/O is stat/read-dir of the root markers, the
// patches/ tree and the declared output roots (for the approximate
// size). Detection must AGREE with a hand-written [[regenerate]] policy,
// not fight it: input sets and output roots deliberately mirror the
// vocabulary a user would write, and Marries (recipe.go) reports overlap
// so inspect does not double-suggest.
package ecosystem

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// Adapter names on GroupSuggestion.Adapter. They match the policy
// package's [[regenerate]].adapter vocabulary for pnpm/npm/uv/pip.
const (
	AdapterPNPM = "pnpm"
	AdapterNPM  = "npm"
	AdapterUV   = "uv"
	AdapterPip  = "pip"
)

// Confidence grades how reproducible a detected group's regeneration is
// from its declared inputs. Lockfile-backed ecosystems (pnpm, npm, uv)
// are high; plain pip is low (Foundation §9.4: unpinned requirements,
// source builds, editable and native installs remain explicit risks).
type Confidence string

// Accepted confidence grades.
const (
	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"
)

// GroupSuggestion is one detected regenerable dependency group
// (Foundation §9.3-9.4). All paths are root-relative with '/'
// separators, matching the policy and actions vocabulary.
type GroupSuggestion struct {
	// GroupID is the stable group identifier; it becomes the
	// actions.Definition ID when Recipe is called. v1 detects at most
	// one group per adapter (markers at the root), so the adapter name
	// is used directly.
	GroupID string
	// Adapter is one of "pnpm", "npm", "uv", "pip".
	Adapter string
	// Outputs are the root-relative output roots the group owns
	// (e.g. "node_modules", ".venv").
	Outputs []string
	// Inputs are the root-relative files regeneration consumes
	// (manifest, lockfile, conditional configuration), in a
	// deterministic order.
	Inputs []string
	// HumanReason is the user-facing one-paragraph explanation of what
	// regeneration means for this group (including what would NOT be
	// retained).
	HumanReason string
	// Present reports whether every declared output already exists on
	// disk. False never suppresses the suggestion.
	Present bool
	// ApproxBytes is the summed LOGICAL size of regular files under the
	// output roots (0 for absent outputs); the caller refines it with
	// allocated sizes from the inventory.
	ApproxBytes int64
	// Confidence grades reproducibility; pip is low, others high.
	Confidence Confidence
}

// Detection is the result of Detect: the regenerable groups found plus
// human-readable notes about trees that were recognized but NOT
// suggested (e.g. a manifest without a pinning lockfile — unpinned
// trees keep the preserve default, Foundation §9.3).
type Detection struct {
	Suggestions []GroupSuggestion
	Notes       []string
}

// Root markers and output roots recognized in v1. Markers are checked
// at the workspace root only.
const (
	markerPackageJSON   = "package.json"
	markerPNPMLock      = "pnpm-lock.yaml"
	markerNPMLock       = "package-lock.json"
	markerNPMRC         = ".npmrc"
	markerPNPMWorkspace = "pnpm-workspace.yaml"
	markerPyproject     = "pyproject.toml"
	markerUVLock        = "uv.lock"
	markerPythonVersion = ".python-version"
	markerRequirements  = "requirements.txt"

	outputNodeModules = "node_modules"
	outputVenv        = ".venv"
)

// pipVenvCandidates lists the conventional virtual-environment
// directory names recognized for a plain-pip workspace, in priority
// order. A pip environment living elsewhere (or in system
// site-packages, outside the workspace) is not claimed as an output in
// v1 — a documented limitation, conservative direction.
var pipVenvCandidates = []string{outputVenv, "venv"}

// Detect inspects wsRoot for root-level package-manager markers and
// returns the regenerable groups found plus explanatory notes. The
// brief's two-value shape ([]GroupSuggestion, error) is widened to a
// Detection struct because unpinned trees must be explained in Notes
// without becoming suggestions.
//
// An error is returned only for an unusable workspace root (missing or
// not a directory). Everything observable about the trees themselves is
// a suggestion or a note, never a failure: detection is an observation,
// not a judgment (Foundation §9.3). Suggestions are emitted in a fixed
// adapter order (pnpm, npm, uv, pip) for determinism; node and python
// groups coexist.
func Detect(wsRoot string) (Detection, error) {
	var det Detection
	info, err := os.Stat(wsRoot)
	if err != nil {
		return det, fmt.Errorf("ecosystem: workspace root: %w", err)
	}
	if !info.IsDir() {
		return det, fmt.Errorf("ecosystem: workspace root is not a directory: %s", wsRoot)
	}

	has := func(rel string) bool {
		_, err := os.Stat(filepath.Join(wsRoot, filepath.FromSlash(rel)))
		return err == nil
	}

	det.detectNode(wsRoot, has)
	det.detectPython(wsRoot, has)
	return det, nil
}

// detectNode covers the pnpm and npm groups plus the node-side notes.
// pnpm wins when both lockfiles are present: a workspace with two
// contradictory lockfiles is ambiguous, and the pnpm lock is the one
// whose frozen install the recipe pins.
func (d *Detection) detectNode(wsRoot string, has func(string) bool) {
	hasPkgJSON := has(markerPackageJSON)
	hasPNPMLock := has(markerPNPMLock)
	hasNPMLock := has(markerNPMLock)

	switch {
	case hasPNPMLock:
		inputs := []string{markerPackageJSON, markerPNPMLock}
		patches, err := patchesInputs(wsRoot)
		if err != nil {
			// A walk failure over patches/ is an infrastructure problem,
			// not an observation; surface it as an error-shaped note and
			// still suggest the group with the lockfile contract.
			d.Notes = append(d.Notes, fmt.Sprintf("patches/ could not be enumerated; it is NOT part of the declared inputs: %v", err))
		} else {
			inputs = append(inputs, patches...)
		}
		if has(markerNPMRC) {
			inputs = append(inputs, markerNPMRC)
		}
		if has(markerPNPMWorkspace) {
			inputs = append(inputs, markerPNPMWorkspace)
		}
		d.add(GroupSuggestion{
			GroupID:     AdapterPNPM,
			Adapter:     AdapterPNPM,
			Outputs:     []string{outputNodeModules},
			Inputs:      inputs,
			HumanReason: "node_modules is regenerable from pnpm-lock.yaml via 'pnpm install --frozen-lockfile'; local edits inside the installed tree would not be retained",
			Confidence:  ConfidenceHigh,
		}, wsRoot)
		if hasNPMLock {
			d.Notes = append(d.Notes,
				"both pnpm-lock.yaml and package-lock.json are present: the pnpm group wins and package-lock.json is not an input (disambiguate by removing one lockfile)")
		}
	case hasNPMLock:
		inputs := []string{markerPackageJSON, markerNPMLock}
		if has(markerNPMRC) {
			inputs = append(inputs, markerNPMRC)
		}
		d.add(GroupSuggestion{
			GroupID:     AdapterNPM,
			Adapter:     AdapterNPM,
			Outputs:     []string{outputNodeModules},
			Inputs:      inputs,
			HumanReason: "node_modules is regenerable from package-lock.json via 'npm ci' (which runs package lifecycle scripts once the action is approved); local edits inside the installed tree would not be retained",
			Confidence:  ConfidenceHigh,
		}, wsRoot)
	}

	if hasPkgJSON && !hasPNPMLock && !hasNPMLock {
		d.Notes = append(d.Notes,
			"package.json present without package-lock.json or pnpm-lock.yaml: the tree is unpinned, no regenerable group is suggested and the default route is preserve")
	}
	if (hasPNPMLock || hasNPMLock) && !hasPkgJSON {
		d.Notes = append(d.Notes,
			"a node lockfile is present without package.json: the manifest is missing, yet it remains a required recipe input (the package-manager install itself would fail)")
	}
}

// detectPython covers the uv and plain-pip groups plus the python-side
// notes. A pyproject.toml without uv.lock suppresses the pip suggestion
// too: such a tree is unpinned either way and keeps the preserve
// default.
func (d *Detection) detectPython(wsRoot string, has func(string) bool) {
	hasPyproject := has(markerPyproject)
	if has(markerUVLock) {
		inputs := []string{markerPyproject, markerUVLock}
		if has(markerPythonVersion) {
			inputs = append(inputs, markerPythonVersion)
		}
		d.add(GroupSuggestion{
			GroupID:     AdapterUV,
			Adapter:     AdapterUV,
			Outputs:     []string{outputVenv},
			Inputs:      inputs,
			HumanReason: ".venv is regenerable from uv.lock via 'uv sync --locked'; a virtual environment is not a portable copy of the Python interpreter, whose version requirement is preserved separately",
			Confidence:  ConfidenceHigh,
		}, wsRoot)
		if !hasPyproject {
			d.Notes = append(d.Notes,
				"uv.lock is present without pyproject.toml: the project manifest is missing, yet it remains a required recipe input")
		}
		return
	}

	if has(markerRequirements) && !hasPyproject {
		outputs := pipVenvOutputs(wsRoot)
		d.add(GroupSuggestion{
			GroupID:     AdapterPip,
			Adapter:     AdapterPip,
			Outputs:     outputs,
			Inputs:      []string{markerRequirements},
			HumanReason: "requirements.txt alone does not pin a reproducible environment (unpinned or ranged requirements, source builds, editable and native installs); v1 keeps pip environments preserved by default and provides no recipe — regeneration requires an explicit custom action",
			Confidence:  ConfidenceLow,
		}, wsRoot)
	}
	if hasPyproject {
		d.Notes = append(d.Notes,
			"pyproject.toml present without uv.lock: no pinned resolution, no regenerable group is suggested and the default route is preserve")
	}
}

// add appends a suggestion after measuring its outputs on disk.
func (d *Detection) add(g GroupSuggestion, wsRoot string) {
	present, approx, notes := measureOutputs(wsRoot, g.Outputs)
	g.Present = present
	g.ApproxBytes = approx
	d.Suggestions = append(d.Suggestions, g)
	d.Notes = append(d.Notes, notes...)
}

// patchesInputs lists every regular file under patches/ as root-relative
// '/'-separated input paths, lexically sorted for determinism. An
// absent patches/ directory yields nil. Symlinks and irregular entries
// (junctions report as irregular on Windows) are skipped, never
// followed.
func patchesInputs(wsRoot string) ([]string, error) {
	root := filepath.Join(wsRoot, "patches")
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rels []string
	err := filepath.WalkDir(root, func(p string, ent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !ent.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(wsRoot, p)
		if err != nil {
			return err
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk patches/: %w", err)
	}
	slices.Sort(rels)
	return rels, nil
}

// pipVenvOutputs returns the first existing conventional virtualenv
// directory, or nil when none exists. A nil Outputs is intentional: the
// group is still suggested (the requirements file is real) but claims
// no owned output root, so Present is false and Marries cannot confirm
// coverage.
func pipVenvOutputs(wsRoot string) []string {
	for _, cand := range pipVenvCandidates {
		if info, err := os.Stat(filepath.Join(wsRoot, cand)); err == nil && info.IsDir() {
			return []string{cand}
		}
	}
	return nil
}

// measureOutputs reports whether every declared output exists on disk
// and sums the LOGICAL size of regular files under each existing
// output, following no links (dirs and links contribute 0, mirroring
// the domain Entry convention). A walk failure yields a note — an
// incomplete approximation is reported, never guessed as exact.
func measureOutputs(wsRoot string, outputs []string) (present bool, approx int64, notes []string) {
	if len(outputs) == 0 {
		return false, 0, nil
	}
	present = true
	for _, out := range outputs {
		p := filepath.Join(wsRoot, filepath.FromSlash(out))
		info, err := os.Stat(p)
		if err != nil {
			present = false
			continue
		}
		if !info.IsDir() {
			approx += info.Size()
			continue
		}
		walkErr := filepath.WalkDir(p, func(_ string, ent fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !ent.Type().IsRegular() {
				return nil
			}
			fi, ferr := ent.Info()
			if ferr != nil {
				return ferr
			}
			approx += fi.Size()
			return nil
		})
		if walkErr != nil {
			notes = append(notes, fmt.Sprintf("size approximation for output %q is incomplete: %v", out, walkErr))
		}
	}
	return present, approx, notes
}
