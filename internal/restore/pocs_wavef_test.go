//go:build security_poc

// Wave F adversarial security PoCs (restore package, in-package so the
// fixture/fakeStore seams are reachable). Opt-in via -tags security_poc
// (Wave C precedent).
//
// F4  FIXED (Wave G secfix, regression form): loadSeal now cross-checks
//
//	the receipt's manifest/inventory digests against the CATALOG row's
//	seal-time digests (the tamper-independent witness, D017) and
//	refuses legacy rows without them. A forged, internally
//	self-consistent P+S pair can no longer publish content the
//	original seal never covered; the PoC below asserts the refusal.
package restore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPoCForgedSealReceiptPublishesUnsealedContent (FIXED, regression
// form): build a legitimate fixture (real scan, correct digests, catalog
// row), then swap BOTH the payload documents and the receipt for
// attacker-authored, internally consistent bytes that inject a file the
// original capture never contained. loadSeal must REFUSE the pair against
// the catalog row's seal-time digests before any staging or publish.
func TestPoCForgedSealReceiptPublishesUnsealedContent(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	injectedRel, forgedInvDigest := forgeSelfConsistentPair(t, f)

	// The catalog row still carries the ORIGINAL seal-time digests and
	// disagrees with the forged receipt — this cross-check is the fix.
	snapRow, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatal(err)
	}
	if snapRow.InventoryDigest == forgedInvDigest {
		t.Fatal("setup error: catalog digest unexpectedly matches the forgery")
	}

	// ---- open() with the forged vault --------------------------------
	dest := filepath.Join(f.parent, "restored")
	res, oerr := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if oerr == nil {
		t.Fatalf("F4 REGRESSION: open() published attacker-injected content as a verified restore (phase FILES_READY, %d entries) while the catalog's seal-time inventory digest %s disagreed with the receipt's %s",
			res.EntriesRestored, snapRow.InventoryDigest, forgedInvDigest)
	}
	var sei *ErrSealInvalid
	if !errors.As(oerr, &sei) {
		t.Fatalf("F4 REGRESSION: refusal is not a typed ErrSealInvalid: %v", oerr)
	}
	if !strings.Contains(joinStrings(sei.Details), snapRow.InventoryDigest) {
		t.Fatalf("F4 REGRESSION: refusal does not cite the catalog's seal-time digest: %v", sei.Details)
	}
	if _, serr := os.Lstat(filepath.Join(dest, injectedRel)); serr == nil {
		t.Fatalf("F4 REGRESSION: injected file %s was published", injectedRel)
	}
	if _, serr := os.Lstat(dest); serr == nil {
		t.Fatalf("F4 REGRESSION: destination %s was created by the refused open", dest)
	}
	assertNoStageDirs(t, f.parent)
}
