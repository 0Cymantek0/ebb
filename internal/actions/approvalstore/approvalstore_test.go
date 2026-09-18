package approvalstore_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"ebb/internal/actions"
	"ebb/internal/actions/approvalstore"
)

func validDef(id string) actions.Definition {
	return actions.Definition{
		ID:      id,
		Argv:    []string{"pnpm", "install", "--frozen-lockfile"},
		Inputs:  []string{"package.json"},
		Outputs: []string{"node_modules"},
		Network: actions.NetworkAllowed,
		Timeout: time.Minute,
	}
}

var (
	tool = actions.ToolIdentity{
		Name:         "pnpm",
		ResolvedPath: `C:\Tools\pnpm.exe`,
		SHA256:       strings64("aa"),
	}
	digests = map[string]string{"package.json": strings64("01")}
)

func TestEmptyStoreApprovesNothing(t *testing.T) {
	dir := t.TempDir()
	st := approvalstore.New(filepath.Join(dir, "approvals.json"))
	def := validDef("node-deps")
	_, err := st.Matches(def, tool, digests)
	var req *actions.ErrApprovalRequired
	if !errors.As(err, &req) || req.ActionID != "node-deps" {
		t.Fatalf("missing approval must be *ErrApprovalRequired, got: %v", err)
	}
	// The document must not have been created by a Match: reading never
	// writes, and nothing is auto-approved.
	if _, err := os.Stat(st.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Matches must not create the store document, stat err: %v", err)
	}
}

func TestApproveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	st := approvalstore.New(path)
	def := validDef("node-deps")

	ap, err := st.Approve(def, tool, digests, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ap.ID == "" || ap.ApprovedBy != "alice" || ap.ArgvDigest != actions.ArgvDigest(def.Argv) {
		t.Fatalf("approval not recorded faithfully: %+v", ap)
	}
	if _, err := time.Parse(time.RFC3339, ap.ApprovedAt); err != nil {
		t.Fatalf("ApprovedAt must be RFC3339, got %q: %v", ap.ApprovedAt, err)
	}

	// A fresh instance over the same document must read the approval back.
	st2 := approvalstore.New(path)
	got, err := st2.Matches(def, tool, digests)
	if err != nil {
		t.Fatalf("fresh instance must match the round-tripped approval: %v", err)
	}
	if got.ID != ap.ID {
		t.Fatalf("round trip changed the approval id: %s vs %s", got.ID, ap.ID)
	}

	// The on-disk document is one valid JSON object with version 1.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Version   int                `json:"version"`
		Approvals []actions.Approval `json:"approvals"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	if raw.Version != 1 || len(raw.Approvals) != 1 || raw.Approvals[0].ActionID != "node-deps" {
		t.Fatalf("unexpected document shape: %+v", raw)
	}
}

func TestReapproveReplacesSameAction(t *testing.T) {
	dir := t.TempDir()
	st := approvalstore.New(filepath.Join(dir, "approvals.json"))
	def := validDef("node-deps")
	if _, err := st.Approve(def, tool, digests, "alice"); err != nil {
		t.Fatal(err)
	}
	changed := validDef("node-deps")
	changed.Argv = []string{"pnpm", "install"}
	if _, err := st.Approve(changed, tool, digests, "bob"); err != nil {
		t.Fatal(err)
	}
	list, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("re-approval must replace, got %d records", len(list))
	}
	if list[0].ArgvDigest != actions.ArgvDigest(changed.Argv) || list[0].ApprovedBy != "bob" {
		t.Fatalf("re-approval did not take effect: %+v", list[0])
	}
}

func TestApproveRejectsInvalidDefinition(t *testing.T) {
	dir := t.TempDir()
	st := approvalstore.New(filepath.Join(dir, "approvals.json"))
	bad := validDef("bad")
	bad.Timeout = 0
	if _, err := st.Approve(bad, tool, digests, "alice"); err == nil {
		t.Fatal("invalid definition must not be recorded")
	}
	list, _ := st.List()
	if len(list) != 0 {
		t.Fatalf("invalid definition left records behind: %+v", list)
	}
}

func TestMatchesStaleDriftDelegates(t *testing.T) {
	dir := t.TempDir()
	st := approvalstore.New(filepath.Join(dir, "approvals.json"))
	def := validDef("node-deps")
	if _, err := st.Approve(def, tool, digests, "alice"); err != nil {
		t.Fatal(err)
	}
	def.Network = actions.NetworkNone
	_, err := st.Matches(def, tool, digests)
	var stale *actions.ErrApprovalStale
	if !errors.As(err, &stale) {
		t.Fatalf("drift must surface as *ErrApprovalStale, got: %v", err)
	}
	if len(stale.Diff) != 1 {
		t.Fatalf("expected one diff line, got: %v", stale.Diff)
	}
}

// TestConcurrentWritersNoLostUpdate hammers one FileApprover from two
// writer goroutines; the in-instance lock plus the atomic rename must
// preserve every approval and never expose a torn document.
func TestConcurrentWritersNoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	st := approvalstore.New(path)

	const perWriter = 25
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				def := validDef(wireID(w, i))
				if _, err := st.Approve(def, tool, digests, "writer"); err != nil {
					t.Errorf("writer %d approve %d: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	list, err := st.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2*perWriter {
		t.Fatalf("lost updates: %d approvals recorded, want %d", len(list), 2*perWriter)
	}
	seen := make(map[string]bool, len(list))
	for _, ap := range list {
		if seen[ap.ActionID] {
			t.Fatalf("duplicate approval for %s", ap.ActionID)
		}
		seen[ap.ActionID] = true
	}
}

// TestConcurrentReadsNeverSeeTornDocument runs a reader that re-parses
// the raw document while writers keep replacing it.
func TestConcurrentReadsNeverSeeTornDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "approvals.json")
	st := approvalstore.New(path)
	if _, err := st.Approve(validDef("seed"), tool, digests, "seed"); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil && transientWindowsSharing(err) {
				// An external observer on Windows can momentarily fail
				// to open while a rename transaction is in flight; that
				// is a retry, not a torn document.
				continue
			}
			if err != nil {
				t.Errorf("read document: %v", err)
				return
			}
			var raw map[string]any
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Errorf("torn document observed: %v", err)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := st.Approve(validDef(wireID(w, i)), tool, digests, "writer"); err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readers.Wait()
}

// TestStoreNeverTouchesSiblingFiles is the behavioral deletion-authority
// guard for the store: decoy siblings must survive every operation
// byte-for-byte.
func TestStoreNeverTouchesSiblingFiles(t *testing.T) {
	dir := t.TempDir()
	decoys := map[string]string{
		"approvals.json.old": "precious old approvals",
		"notes.txt":          "do not touch",
	}
	for name, content := range decoys {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	st := approvalstore.New(filepath.Join(dir, "approvals.json"))
	if _, err := st.Approve(validDef("node-deps"), tool, digests, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Matches(validDef("node-deps"), tool, digests); err != nil {
		t.Fatal(err)
	}
	for name, want := range decoys {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("decoy %s disturbed: %v", name, err)
		}
		if string(b) != want {
			t.Fatalf("decoy %s modified: %q", name, b)
		}
	}
	// No stray temp files remain next to the document after a clean save.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "approvals.json" && decoys[e.Name()] == "" {
			t.Fatalf("stray artifact left behind: %s", e.Name())
		}
	}
}

func wireID(w, i int) string {
	return fmt.Sprintf("action-w%d-i%02d", w, i)
}

// transientWindowsSharing reports a transient sharing-violation open
// failure on Windows.
func transientWindowsSharing(err error) bool {
	var errno syscall.Errno
	return runtime.GOOS == "windows" &&
		errors.As(err, &errno) &&
		(errno == syscall.Errno(32) || errno == syscall.Errno(5))
}

func strings64(seed string) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = "0123456789abcdef"[(int(seed[0])+i)%16]
	}
	return string(out)
}
