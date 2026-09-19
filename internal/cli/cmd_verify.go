// cmdVerify implements `ebb verify <snapshot-id>` (Foundation §17.1,
// §11.4, §4.1): refresh the evidence of one sealed retained snapshot
// with an EXPLICIT scope. Default scope = seal/document readback +
// coverage re-derivation (cheap: one listing plus two document dumps);
// `--content` adds the full readback of every preserved byte (expensive:
// the whole payload is re-read and digest-checked — one streaming tar
// dump when the backend supports it, one backend call per file
// otherwise).
//
// Checks are NAMED and individually pass/fail (§4.1: a verification
// result names its checks; it is never a free-form "safe=true"):
//
//	seal-receipt       the §16.4 receipt reads back, parses strictly and
//	                   cross-checks against the catalog row
//	payload-documents  manifest + accounting document read back through
//	                   the backend and match the receipt's digests (I12)
//	coverage-complete  the payload tree holds exactly the expected nodes
//	                   (derived from the retained inventory through
//	                   lifecycle.ExpectedTreeFor — the same pure rules the
//	                   capture itself used)
//	content-readback   (--content) every preserved file's bytes are
//	                   dumped and compared to the independent digest
//
// Exit contract: 0 all checks pass; 2 unknown/malformed id; 3 blocked
// (trim-kind or seal-kind row, unsealed payload — those are not
// verifiable in this form); 4 a check failed; 7 vault; 130 cancelled.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/restore"
	"ebb/internal/version"
)

// verifyCheck is one named check's outcome (§4.1).
type verifyCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | skipped
	Detail string `json:"detail,omitempty"`
}

// verifyDetails is the --json payload of a verify run.
type verifyDetails struct {
	Workspace    string            `json:"workspace"`
	Kind         string            `json:"kind"`
	CreatedAt    string            `json:"created_at"`
	Scope        string            `json:"scope"`
	Checks       []verifyCheck     `json:"checks"`
	ToolVersions map[string]string `json:"tool_versions"`
	// ReceiptTime/ReceiptChecks are what the seal recorded when the
	// capture was verified (evidence has a time and a scope, §11.4).
	ReceiptTime   string   `json:"receipt_time"`
	ReceiptChecks []string `json:"receipt_checks"`
	// Facts from the retained evidence.
	InventoryCount  int64 `json:"inventory_count"`
	EntriesRetained int64 `json:"entries_retained"`
	PreservedBytes  int64 `json:"preserved_bytes"`
}

// verifyReport accumulates the checks inside the vault closure.
type verifyReport struct {
	details verifyDetails
	failed  bool
}

func (r *verifyReport) pass(name string) {
	r.details.Checks = append(r.details.Checks, verifyCheck{Name: name, Status: "pass"})
}

func (r *verifyReport) fail(name string, detail string) {
	r.failed = true
	r.details.Checks = append(r.details.Checks, verifyCheck{Name: name, Status: "fail", Detail: detail})
}

func (r *verifyReport) skip(name, why string) {
	r.details.Checks = append(r.details.Checks, verifyCheck{Name: name, Status: "skipped", Detail: why})
}

func cmdVerify(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	content := fs.Bool("content", false, "full readback of every preserved byte (expensive: the whole payload is re-read and digest-checked)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb verify: takes exactly one snapshot id (32 hex chars; see `ebb status`)")
		return ExitUsage
	}
	idArg := fs.Arg(0)
	if _, perr := domain.ParseID(idArg); perr != nil {
		fmt.Fprintf(streams.Err, "ebb verify: %v (got %q)\n", perr, idArg)
		return ExitUsage
	}
	snapID := domain.SnapshotID(idArg)

	env := newEnvelope("verify", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	snap, gerr := sess.cat.GetSnapshot(snapID)
	if gerr != nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf(
			"verify %s: no such snapshot in the catalog. Safe action: check `ebb status` for snapshot ids", idArg))
	}
	// Scope gate: v1 verifies full workspace payloads (park/snapshot
	// kinds). A trim's authoritative material is its removal plan and a
	// seal-only row has no payload — neither is verifiable in this form.
	switch {
	case snap.Kind == catalog.SnapshotKindTrim:
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
			"%s [verify %s]: a trim snapshot's authoritative material is its sealed removal plan, which v1 verify does not re-scope (its seal was verified at trim time). Safe action: verify a park/snapshot-kind snapshot, or inspect the trim with `ebb status`",
			restore.CodeNotOpenable, idArg))
	case snap.Kind == catalog.SnapshotKindSeal:
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
			"%s [verify %s]: a seal-only record has no payload to verify. Safe action: nothing to check; see `ebb status`",
			restore.CodeNotOpenable, idArg))
	case snap.PayloadBackendID == "" || snap.SealBackendID == "":
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
			"%s [verify %s]: the payload is UNSEALED (payload/seal backend id missing); an unverified capture cannot be given fresh evidence. Safe action: inspect with `ebb status` / `ebb recover <operation-id>` (§11.3)",
			restore.CodeNotOpenable, idArg))
	}
	ws, werr := sess.cat.GetWorkspace(snap.WorkspaceID)
	if werr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(werr),
			fmt.Sprintf("verify %s: snapshot has no workspace row: %v", idArg, werr))
	}

	scope := "coverage+documents"
	if *content {
		scope = "coverage+documents+content"
	}
	rep := verifyReport{details: verifyDetails{
		Workspace: ws.Name, Kind: snap.Kind, CreatedAt: snap.CreatedAt,
		Scope: scope, Checks: []verifyCheck{},
		ToolVersions: map[string]string{"ebb": version.Version, "restic-target": ResticTarget},
	}}

	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		// ---- check 1+2: seal receipt + payload documents --------------
		ev, eerr := restore.LoadRetainedEvidence(ctx, sess.store,
			restore.VaultRef{RepoDir: repoDir, Passfile: passfile}, snapID, snap)
		if eerr != nil {
			var sealInvalid *restore.ErrSealInvalid
			var docs *restore.ErrVerification
			switch {
			case errors.As(eerr, &sealInvalid):
				rep.fail("seal-receipt", strings.Join(sealInvalid.Details, "; "))
				rep.skip("payload-documents", "the seal receipt did not validate")
				rep.skip("coverage-complete", "no verified documents to derive the expectation from")
				if *content {
					rep.skip("content-readback", "coverage did not run")
				}
			case errors.As(eerr, &docs):
				rep.pass("seal-receipt")
				rep.fail("payload-documents", strings.Join(docs.Details, "; "))
				rep.skip("coverage-complete", "the retained documents failed their digest gate (I12)")
				if *content {
					rep.skip("content-readback", "coverage did not run")
				}
			default:
				return eerr // infra failure (store/vault) — classified below
			}
			return errVerifyFailed
		}
		rep.pass("seal-receipt")
		rep.pass("payload-documents")
		rep.details.ReceiptTime = ev.Receipt.Time
		rep.details.ReceiptChecks = ev.Receipt.Checks
		for k, v := range ev.Receipt.ToolVersions {
			rep.details.ToolVersions[k] = v
		}
		rep.details.InventoryCount = ev.Manifest.InventoryCount
		rep.details.EntriesRetained = ev.PreservedEntries
		rep.details.PreservedBytes = ev.PreservedBytes

		// ---- check 3: coverage re-derivation --------------------------
		ls, lerr := sess.store.Ls(ctx, repoDir, passfile, snap.PayloadBackendID)
		if lerr != nil {
			return lerr
		}
		expected, readbackFiles := lifecycle.ExpectedTreeFor(ev.Retained, ev.WsPrefix)
		addExpectedFile(expected, ev.OpDirName, manifestDocName, ev.Manifest.ManifestBytes)
		addExpectedFile(expected, ev.OpDirName, ev.Manifest.InventoryPath, ev.Manifest.InventoryBytes)
		addExpectedFile(expected, ev.OpDirName, policyDocName, ev.Manifest.PolicyBytes)
		if problems := compareTree(ls, expected, []string{ev.WsPrefix, ev.OpDirName}); len(problems) > 0 {
			rep.fail("coverage-complete", strings.Join(problems, "; "))
			if *content {
				rep.skip("content-readback", "coverage failed")
			}
			return errVerifyFailed
		}
		rep.pass("coverage-complete")

		// ---- check 4 (--content): full content readback ---------------
		if *content {
			fmt.Fprintf(streams.Err, "content scope: full readback of %d preserved file(s) through the backend (every preserved byte is re-read and digest-checked; this can take a while)\n",
				len(readbackFiles))
			// Shared executor: the SAME transport and derivation the
			// capture's own §11.4 gate and crash-recovery re-verification
			// use (lifecycle.VerifyReadback) — a re-verification that
			// disagreed with the capture's own evidence would be vacuous.
			// It streams the whole tree as ONE tar archive when the
			// backend supports it (domain.TreeTarDumper), else one
			// DumpFile per file.
			verr := lifecycle.VerifyReadback(ctx, sess.store, repoDir, passfile, snap.PayloadBackendID, readbackFiles)
			if verr != nil {
				if errors.Is(verr, context.Canceled) || errors.Is(verr, context.DeadlineExceeded) {
					return verr
				}
				var ev *lifecycle.ErrVerification
				if errors.As(verr, &ev) {
					rep.fail("content-readback", strings.Join(ev.Details, "; "))
					return errVerifyFailed
				}
				return verr // infra failure (store/vault) — classified below
			}
			rep.pass("content-readback")
		}
		return nil
	})
	if cErr != nil && !isVerifyFailed(cErr) {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("verify %s: %s", idArg, codedWithSafeAction(cErr)))
	}

	env.SnapshotID = idArg
	env.WorkspaceID = string(ws.ID)
	env.Details = rep.details
	env.Conditions = []string{"scope:" + scope}
	if rep.failed {
		env.Outcome = outcomeForExit(ExitCaptureVerify)
		emit(env, *jsonOut, streams, renderVerifyHuman(rep.details))
		return ExitCaptureVerify
	}
	env.Outcome = "ok"
	emit(env, *jsonOut, streams, renderVerifyHuman(rep.details))
	return ExitOK
}

// errVerifyFailed marks a failed named check (mapped to exit 4); it never
// reaches the user directly — the check table carries the detail.
var errVerifyFailed = fmt.Errorf("verify: a named check failed")

func isVerifyFailed(err error) bool { return err == errVerifyFailed }

// The frozen op-dir document names (mirror internal/lifecycle/manifest.go;
// the authoritative values arrive in the evidence itself for inventory
// and via the digests for the others).
const (
	manifestDocName = "manifest.json"
	policyDocName   = "policy.toml"
)

// addExpectedFile adds "<opDir>/<name>" (a file of n bytes) plus its
// ancestor directories to the expected tree — mirroring
// lifecycle.addExpectedPath's semantics for the CLI-side comparison.
func addExpectedFile(m map[string]lifecycle.ExpectedNode, opDir, name string, n int64) {
	segs := strings.Split(opDir+"/"+name, "/")
	for i := 1; i < len(segs); i++ {
		m["/"+strings.Join(segs[:i], "/")] = lifecycle.ExpectedNode{Kind: domain.KindDir}
	}
	m["/"+opDir+"/"+name] = lifecycle.ExpectedNode{Kind: domain.KindFile, Size: n}
}

// compareTree mirrors lifecycle.verifyCoverage's exact-match semantics
// (missing/unexpected/duplicate nodes, kind and size mismatches, prefix
// gating — I04). Duplicated minimally at the presentation layer because
// lifecycle's helper is unexported and this package's helper budget was
// spent on the derivation (ExpectedTreeFor).
func compareTree(ls []domain.TreeEntry, expected map[string]lifecycle.ExpectedNode, prefixes []string) []string {
	prefixSet := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		prefixSet["/"+p] = true
	}
	var details []string
	seen := make(map[string]bool, len(ls))
	for _, e := range ls {
		trimmed := strings.TrimPrefix(e.Path, "/")
		first := trimmed
		if i := strings.IndexByte(trimmed, '/'); i >= 0 {
			first = trimmed[:i]
		}
		if !prefixSet["/"+first] {
			details = append(details, fmt.Sprintf("unexpected tree entry %q (outside declared prefixes %v; I04)", e.Path, prefixes))
			continue
		}
		if seen[e.Path] {
			details = append(details, fmt.Sprintf("duplicate tree entry %q", e.Path))
			continue
		}
		seen[e.Path] = true
		want, ok := expected[e.Path]
		if !ok {
			details = append(details, fmt.Sprintf("unexpected tree entry %q not in the retained inventory (I04)", e.Path))
			continue
		}
		if e.Kind != want.Kind {
			details = append(details, fmt.Sprintf("%s: tree kind %q, expected %q", e.Path, e.Kind, want.Kind))
			continue
		}
		if want.Kind == domain.KindFile && e.Size != want.Size {
			details = append(details, fmt.Sprintf("%s: tree size %d, expected %d", e.Path, e.Size, want.Size))
		}
	}
	for path, want := range expected {
		if !seen[path] {
			details = append(details, fmt.Sprintf("expected %s (%s) missing from snapshot tree", path, want.Kind))
		}
	}
	sort.Strings(details)
	return details
}

// renderVerifyHuman renders the §4.1 report: named checks with pass/fail
// per check and the tool versions that produced the evidence.
func renderVerifyHuman(d verifyDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	outcome := "PASS"
	if hasFailedCheck(d) {
		outcome = "FAIL"
	}
	line("verify %s of workspace %q (%s): %s\n", d.Kind, d.Workspace, d.Scope, outcome)
	line("  snapshot created %s\n", d.CreatedAt)
	for _, c := range d.Checks {
		switch c.Status {
		case "pass":
			line("  check %s: pass\n", c.Name)
		case "skipped":
			line("  check %s: skipped (%s)\n", c.Name, c.Detail)
		default:
			line("  check %s: FAIL — %s\n", c.Name, c.Detail)
		}
	}
	line("  retained evidence: %d of %d inventory entries preserved (%s)\n",
		d.EntriesRetained, d.InventoryCount, HumanBytes(d.PreservedBytes))
	if d.ReceiptTime != "" {
		line("  seal recorded its verification at %s (checks: %s)\n", d.ReceiptTime, strings.Join(d.ReceiptChecks, ", "))
	}
	tools := make([]string, 0, len(d.ToolVersions))
	for k, v := range d.ToolVersions {
		tools = append(tools, k+" "+v)
	}
	sort.Strings(tools)
	line("  tools: %s\n", strings.Join(tools, "; "))
	if hasFailedCheck(d) {
		line("  keep the snapshot pinned; no removal or forget is authorized on failed evidence (I12)\n")
	}
	return b.String()
}

func hasFailedCheck(d verifyDetails) bool {
	for _, c := range d.Checks {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}
