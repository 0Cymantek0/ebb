//go:build security_poc

package lifecycle

// Wave G adversarial security PoCs (lifecycle package). Opt-in via
// -tags security_poc (Wave C/F precedent).
//
// G4  CancelOperation on a SEALED operation never probes the
//
//	deterministic quarantine sibling (recoverSealed does, D020/F5):
//	canceling exactly in the F5 crash window — quarantine rename done,
//	SEALED→QUARANTINED CAS not — strands the user's entire workspace at
//	the opaque sibling path with no durable pointer: the operation goes
//	terminal CANCELED (recover will never mention the tree again), the
//	op dir / seal dir / journal are deleted, and the report even claims
//	"live root intact; removal never started", which is false in this
//	state.
//
// G5-G7 are §11.4 tar-transport attack probes in guard-holds form: each
// asserts a hostile archive shape is REFUSED by the readback gate that
// authorizes deletion; a failure ("G* CONFIRMED") means the gate opened.
//
// A PoC test that FAILS prints "G* CONFIRMED" — the failure IS the
// reproduced vulnerability.

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
)

func TestPoCCancelSealedInQuarantineCrashWindowStrandsWorkspace(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseSealed {
		t.Fatalf("phase = %s, want SEALED (fixture problem)", got)
	}
	// The F5 crash point: the quarantine rename happened, nothing after.
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(root, quar); err != nil {
		t.Fatal(err)
	}

	// The user follows the crash-window advice and cancels the stuck op.
	crep, cerr := h.coord().CancelOperation(context.Background(), h.vault, st.opID)
	if cerr == nil && crep.PhaseAfter == catalog.PhaseCanceled {
		// The workspace's whole tree still sits at the quarantine sibling…
		mustExist(t, filepath.Join(quar, "notes.md"))
		// …the operation is terminal (recover will never reconcile or even
		// mention it)…
		if got := h.phaseOf(t, st.opID); got == catalog.PhaseCanceled {
			// …and the local scratch that named the op (journal, op dir,
			// seal dir) has been removed by the cancel itself.
			actions := ""
			for _, a := range crep.Actions {
				actions += a + " | "
			}
			t.Fatalf("G4 CONFIRMED: cancel of the SEALED op in the quarantine-rename crash window "+
				"stranded the entire workspace at %s with no durable pointer — phase CANCELED (terminal), "+
				"quarantine sibling never probed or mentioned in the report (actions: %q); the op dir/seal dir/journal "+
				"scratch was cleaned, so only filesystem archaeology can find the tree again", quar, actions)
		}
	}
	// Fixed build: cancel must refuse (or reconcile the sibling first)
	// when the quarantine rename already happened.
}

// ---- §11.4 tar-transport attack probes ------------------------------------

func tarMember(tw *tar.Writer, name string, typeflag byte, body string) {
	size := int64(len(body))
	if typeflag == tar.TypeLink {
		size = 0 // link members carry no content body
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: typeflag}); err != nil {
		panic(err)
	}
	if body != "" {
		if _, err := tw.Write([]byte(body)); err != nil {
			panic(err)
		}
	}
}

// rawUstarHeader builds one 512-byte ustar header block by hand (valid
// checksum), letting probes spell member names Go's tar.Writer refuses
// (e.g. a regular member with a trailing slash).
func rawUstarHeader(name string, size int64) [512]byte {
	var blk [512]byte
	copy(blk[0:], name)
	copy(blk[100:], "0000644\x00") // mode
	copy(blk[108:], "0000000\x00") // uid
	copy(blk[116:], "0000000\x00") // gid
	copy(blk[124:], fmt.Sprintf("%011o\x00", size))
	copy(blk[136:], fmt.Sprintf("%011o\x00", 0)) // mtime
	blk[156] = '0'                               // TypeReg
	copy(blk[257:], "ustar\x00")
	copy(blk[263:], "00")
	for i := 148; i < 156; i++ {
		blk[i] = ' '
	}
	var sum int64
	for _, b := range blk {
		sum += int64(b)
	}
	copy(blk[148:], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

// TestPoCTarDuplicateViaAlternateSpellingRejected: two members that
// normalize to the SAME expected path ("ws/a.txt" and a trailing-slash
// spelling of it) must trip the duplicate-name gate, not double-count
// as an allowed re-send.
func TestPoCTarDuplicateViaAlternateSpellingRejected(t *testing.T) {
	member := func(name, body string) []byte {
		hdr := rawUstarHeader(name, int64(len(body)))
		content := append([]byte(body), make([]byte, (512-len(body)%512)%512)...)
		return append(hdr[:], content...)
	}
	archive := append(member("ws/a.txt", "tar transport alpha\n"),
		member("ws/a.txt/", "DIFFERENT CONTENT !!\n")...)
	archive = append(archive, make([]byte, 1024)...) // end-of-archive marker

	store := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1, rawTar: archive}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("tar transport alpha\n"))}}
	err := verifyReadback(context.Background(), store, "r", "p", "s", files)
	if err == nil {
		t.Fatalf("G5 CONFIRMED: an expected file sent twice under slash-variant spellings " +
			"(second copy with different content) passed readback verification")
	}
	if !strings.Contains(err.Error(), "duplicate tar member") {
		t.Fatalf("duplicate-via-spelling surfaced as something else: %v", err)
	}
}

// TestPoCTarHardlinkMemberForExpectedFileRejected: an expected file
// delivered ONLY as a hardlink member (content by reference) must fail
// as missing — readback may not substitute link targets for content.
func TestPoCTarHardlinkMemberForExpectedFileRejected(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tarMember(tw, "ws/other.txt", tar.TypeReg, "x\n")
	if err := tw.WriteHeader(&tar.Header{Name: "ws/a.txt", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "ws/other.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	store := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1, rawTar: buf.Bytes()}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("x\n"))}}
	err := verifyReadback(context.Background(), store, "r", "p", "s", files)
	if err == nil || !strings.Contains(err.Error(), "missing from the tar dump") {
		t.Fatalf("G6 CONFIRMED or unexpected: a hardlink member stood in for an expected file's content: %v", err)
	}
}

// TestPoCTarGiantDeclaredSizeBoundedMemory: a member header declaring a
// terabyte of content with almost none present must fail cleanly via
// the truncated-content gate, never by trusting hdr.Size for
// allocation.
func TestPoCTarGiantDeclaredSizeBoundedMemory(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tarMember(tw, "ws/a.txt", tar.TypeReg, "tar transport alpha\n")
	if err := tw.WriteHeader(&tar.Header{Name: "ws/big.bin", Mode: 0o644, Size: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("2 bytes")); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close() // errors on the short member write; the raw bytes are what matters
	store := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1, rawTar: buf.Bytes()}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("tar transport alpha\n"))}}
	err := verifyReadback(context.Background(), store, "r", "p", "s", files)
	if err == nil {
		t.Fatalf("G7 CONFIRMED: an archive with a member declaring 1 TiB and delivering 7 bytes " +
			"passed readback verification")
	}
}
