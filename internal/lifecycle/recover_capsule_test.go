package lifecycle

// recover_capsule_test.go — default-suite regressions for the Wave J
// review J1 reconciliation path of the capsule transports: a crashed
// export/import operation (any non-terminal EXPORT_*/IMPORT_* phase) is
// closed by CancelOperation — idempotently, releasing the export's
// duration pin audit-only and naming (never deleting) what the transport
// left behind — while plain Recover stays report-only and a kind/phase
// vocabulary mismatch is refused as journal divergence.

import (
	"context"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// capsuleOpFor opens a capsule-transport operation and walks it to the
// given phase, exactly the durable state a crash would leave.
func capsuleOpFor(t *testing.T, h *harness, kind, phase string) (domain.OperationID, domain.WorkspaceID) {
	t.Helper()
	ws := newWSID()
	if err := capsuleCat(t, h).EnsureWorkspace(ws, "capsule-ws"); err != nil {
		t.Fatal(err)
	}
	opID, err := capsuleCat(t, h).BeginOperation(ws, kind, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string][][2]string{
		catalog.PhaseExportCopying: {
			{catalog.PhasePlanned, catalog.PhaseExportPlanned},
			{catalog.PhaseExportPlanned, catalog.PhaseExportCopying},
		},
		catalog.PhaseImportVerifying: {
			{catalog.PhasePlanned, catalog.PhaseImportPlanned},
			{catalog.PhaseImportPlanned, catalog.PhaseImportCopying},
			{catalog.PhaseImportCopying, catalog.PhaseImportVerifying},
		},
	}[phase]
	for _, s := range steps {
		if err := capsuleCat(t, h).AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatal(err)
		}
	}
	return opID, ws
}

// TestRecoverReportOnlyForCapsuleTransportPhases pins plain Recover's
// contract on the export/import phases: report-only, phase unchanged,
// next action naming --cancel.
func TestRecoverReportOnlyForCapsuleTransportPhases(t *testing.T) {
	h := newHarness(t)
	opID, _ := capsuleOpFor(t, h, catalog.OpKindExport, catalog.PhaseExportCopying)

	rep, err := h.coord().Recover(context.Background(), h.vault, opID)
	if err != nil {
		t.Fatalf("recover on EXPORT_COPYING: %v", err)
	}
	if rep.PhaseAfter != catalog.PhaseExportCopying {
		t.Fatalf("plain recover changed the phase: %s", rep.PhaseAfter)
	}
	if !strings.Contains(rep.NextAction, "--cancel") {
		t.Fatalf("next action = %q, want --cancel advice", rep.NextAction)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseExportCopying {
		t.Fatalf("durable phase = %s, want unchanged", got)
	}
}

// TestCancelCapsuleTransportClosesAndNamesLeftovers proves the J1 escape
// hatch at the lifecycle seam: an import op crashed at IMPORT_VERIFYING
// with the copied destination ids recorded on its row closes to
// CANCELED, the ids are NAMED in the report (never deleted), a second
// cancel is an idempotent no-op, and an export op whose journal
// vocabulary does not match its kind is refused as divergence.
func TestCancelCapsuleTransportClosesAndNamesLeftovers(t *testing.T) {
	h := newHarness(t)
	opID, ws := capsuleOpFor(t, h, catalog.OpKindImport, catalog.PhaseImportVerifying)
	// The CLI's durable record of what the transport copied (crash
	// between the transport and the registration).
	const dstPayload, dstSeal = "dstpayload0000", "dstseal0000"
	if err := capsuleCat(t, h).SetBackendRefs(opID, dstPayload, dstSeal); err != nil {
		t.Fatal(err)
	}

	rep, err := h.coord().CancelOperation(context.Background(), h.vault, opID)
	if err != nil {
		t.Fatalf("cancel on IMPORT_VERIFYING: %v", err)
	}
	if rep.PhaseAfter != catalog.PhaseCanceled {
		t.Fatalf("phase after cancel = %s, want CANCELED", rep.PhaseAfter)
	}
	named := false
	for _, r := range rep.Remaining {
		if strings.Contains(r, dstPayload) && strings.Contains(r, dstSeal) {
			named = true
		}
	}
	if !named {
		t.Fatalf("cancel report does not name the leaked destination ids %s/%s: %v", dstPayload, dstSeal, rep.Remaining)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseCanceled {
		t.Fatalf("durable phase = %s, want CANCELED", got)
	}
	if active, err := capsuleCat(t, h).ActiveOperations(ws); err != nil || len(active) != 0 {
		t.Fatalf("active ops after cancel = %v (%v)", active, err)
	}

	// Idempotent: a rerun reports already-canceled without error.
	rep, err = h.coord().CancelOperation(context.Background(), h.vault, opID)
	if err != nil {
		t.Fatalf("idempotent cancel rerun: %v", err)
	}
	if rep.PhaseAfter != catalog.PhaseCanceled {
		t.Fatalf("rerun phase = %s, want CANCELED", rep.PhaseAfter)
	}
}

// TestCancelCapsuleTransportReleasesExportPin covers the export flavor:
// the duration pin taken by the crashed export is released audit-only
// (the snapshot keeps its own pinned flag, I07).
func TestCancelCapsuleTransportReleasesExportPin(t *testing.T) {
	h := newHarness(t)
	opID, ws := capsuleOpFor(t, h, catalog.OpKindExport, catalog.PhaseExportCopying)
	snap := catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws, Kind: catalog.SnapshotKindPark,
		PayloadBackendID: "p1",
	}
	if _, err := capsuleCat(t, h).RecordSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	if err := capsuleCat(t, h).Pin(snap.ID, "export:"+string(opID)); err != nil {
		t.Fatal(err)
	}

	if _, err := h.coord().CancelOperation(context.Background(), h.vault, opID); err != nil {
		t.Fatalf("cancel on EXPORT_COPYING: %v", err)
	}
	fresh, err := capsuleCat(t, h).GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	sawRelease := false
	for _, r := range fresh.PinReasons {
		if r == "unpin:export:"+string(opID) {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Fatalf("duration pin not released (audit: %v)", fresh.PinReasons)
	}
	if !fresh.Pinned {
		t.Error("cancel dropped the snapshot's own pinned flag (I07 violation)")
	}
}

// TestCancelCapsuleTransportRefusesVocabularyMismatch proves a phase
// belonging to the export vocabulary on an import-kind row (or vice
// versa) is treated as journal divergence, never silently closed.
func TestCancelCapsuleTransportRefusesVocabularyMismatch(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	if err := capsuleCat(t, h).EnsureWorkspace(ws, "mismatch-ws"); err != nil {
		t.Fatal(err)
	}
	opID, err := capsuleCat(t, h).BeginOperation(ws, catalog.OpKindImport, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range [][2]string{
		{catalog.PhasePlanned, catalog.PhaseExportPlanned},
		{catalog.PhaseExportPlanned, catalog.PhaseExportCopying},
	} {
		if err := capsuleCat(t, h).AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.coord().CancelOperation(context.Background(), h.vault, opID); err == nil {
		t.Fatal("cancel accepted an import-kind row in an EXPORT_* phase — vocabulary mismatch must refuse")
	} else {
		var jm *ErrJournalMismatch
		if !asErr(err, &jm) {
			t.Fatalf("cancel mismatch error is not ErrJournalMismatch: %v", err)
		}
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseExportCopying {
		t.Fatalf("refused cancel changed the phase: %s", got)
	}
}

// asErr is a tiny generic errors.As helper (the package's tests each
// declare their own; this one stays local to this file).
func asErr[T error](err error, target *T) bool {
	for err != nil {
		if e, ok := err.(T); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// capsuleCat opens one catalog handle for direct row setup/inspection,
// registered for the harness's pooled-close cleanup.
func capsuleCat(t *testing.T, h *harness) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Open(h.catPath)
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	h.opened = append(h.opened, c)
	return c
}
