// fakerestic is the fake restic backend for the freezer tests (D040 tier
// 3): it implements exactly the argv surface internal/storage/restic
// drives on the freeze path (`backup --stdin --stdin-filename`, raw
// `dump`, `init`) with a file-backed store, so the streaming pipeline is
// exercised deterministically without a real repository. The REAL restic
// conformance lives in the restic package's own opt-in suite.
//
// Control rides the REPOSITORY directory (no test env reaches a restic
// child by construction — the adapter's env discipline drops everything
// but the OS substrate): control files live under <repo>/fake-control/.
//
//	<repo>/fake-control/fail-backup   backup consumes stdin, stores the
//	                                  snapshot, then exits 3 with error
//	                                  records (the real restic
//	                                  stores-incomplete-on-source-error
//	                                  behavior, probe Q4a)
//	<repo>/fake-control/tamper        dump flips the first stored byte
//	                                  (readback digest mismatch)
//	<repo>/fake-control/restic.log    append-only invocation log
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const fakeRepoID = "f4kef4kef4kef4kef4kef4kef4kef4kef4kef4kef4kef4kef4kef4kef4ke"

type snapRecord struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
}

func main() {
	args := os.Args[1:]
	repo := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--repo" && i+1 < len(args) {
			repo = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if repo == "" || len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "fakerestic: expected `--repo <dir> <subcommand>`")
		os.Exit(2)
	}
	ctlDir := filepath.Join(repo, "fake-control")
	logf := func(format string, a ...any) {
		_ = os.MkdirAll(ctlDir, 0o755)
		f, err := os.OpenFile(filepath.Join(ctlDir, "restic.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		fmt.Fprintf(f, format+"\n", a...)
		f.Close()
	}
	ctlExists := func(name string) bool {
		_, err := os.Stat(filepath.Join(ctlDir, name))
		return err == nil
	}
	exitError := func(code int, msg string) {
		fmt.Fprintf(os.Stderr, `{"message_type":"exit_error","code":%d,"message":%q}`+"\n", code, msg)
		os.Exit(code)
	}

	sub := rest[0]
	logf("start %s", strings.Join(rest, " "))

	// Password discipline: the secret only ever arrives through
	// RESTIC_PASSWORD_FILE (the adapter never puts it in argv).
	if sub == "backup" || sub == "dump" {
		passfile := os.Getenv("RESTIC_PASSWORD_FILE")
		if passfile == "" {
			exitError(12, "RESTIC_PASSWORD_FILE is not set")
		}
		pw, err := os.ReadFile(passfile)
		if err != nil || len(strings.TrimSpace(string(pw))) == 0 {
			exitError(12, "the password file is unreadable or empty")
		}
		if _, err := os.Stat(filepath.Join(repo, "config")); err != nil {
			exitError(10, "repository does not exist")
		}
	}

	switch sub {
	case "init":
		if err := os.MkdirAll(filepath.Join(repo, "keys"), 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic init:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(repo, "config"),
			[]byte(fmt.Sprintf(`{"version":2,"id":%q,"chunker_polynomial":"25b468838dcb75"}`, fakeRepoID)), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic init:", err)
			os.Exit(1)
		}
		fmt.Println("created restic repository at", repo)

	case "backup":
		filename := "stdin"
		stdin := false
		for i := 1; i < len(rest); i++ {
			switch rest[i] {
			case "--stdin":
				stdin = true
			case "--stdin-filename":
				if i+1 < len(rest) {
					filename = rest[i+1]
					i++
				}
			}
		}
		if !stdin {
			fmt.Fprintln(os.Stderr, "fakerestic: backup without --stdin is not implemented")
			os.Exit(2)
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			exitError(3, "reading stdin failed")
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		id := digest
		blobDir := filepath.Join(repo, "blobs")
		if err := os.MkdirAll(blobDir, 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic backup:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filepath.Join(blobDir, id), data, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic backup:", err)
			os.Exit(1)
		}
		snaps := loadSnaps(repo)
		snaps = append(snaps, snapRecord{ID: id, Filename: filename,
			SHA256: digest, Bytes: int64(len(data))})
		if err := saveSnaps(repo, snaps); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic backup:", err)
			os.Exit(1)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		fmt.Println(`{"message_type":"status","percent_done":0.5,"total_files":1}`)
		fmt.Printf(`{"message_type":"summary","snapshot_id":%q,"dry_run":false,"backup_end":%q,"total_files_processed":1}`+"\n", id, now)
		if ctlExists("fail-backup") {
			// The probe-Q4a shape: the snapshot IS stored (and the
			// summary names it), the process still fails, and the
			// failure rides stderr records.
			fmt.Fprintf(os.Stderr, `{"message_type":"error","error":{"message":"read stdin: input/output error"},"during":"archival","item":"stdin"}`+"\n")
			exitError(3, "Warn: source read error")
		}

	case "dump":
		if len(rest) < 3 {
			fmt.Fprintln(os.Stderr, "fakerestic: expected `dump <snapID> <path>`")
			os.Exit(2)
		}
		wantID, path := rest[1], strings.TrimPrefix(rest[2], "/")
		var rec *snapRecord
		for _, s := range loadSnaps(repo) {
			if strings.HasPrefix(s.ID, wantID) {
				s := s
				rec = &s
				break
			}
		}
		if rec == nil {
			fmt.Fprintf(os.Stderr, "Fatal: no matching ID found for prefix %q\n", wantID)
			os.Exit(1)
		}
		if rec.Filename != path {
			fmt.Fprintf(os.Stderr, "Fatal: path %q is not in snapshot %s\n", path, rec.ID)
			os.Exit(1)
		}
		data, err := os.ReadFile(filepath.Join(repo, "blobs", rec.ID))
		if err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic dump:", err)
			os.Exit(1)
		}
		if ctlExists("tamper") && len(data) > 0 {
			data[0] ^= 0xFF
		}
		if _, err := os.Stdout.Write(data); err != nil {
			fmt.Fprintln(os.Stderr, "fakerestic dump: write:", err)
			os.Exit(1)
		}

	case "version", "--version":
		fmt.Println("restic 0.19.1-fake")

	default:
		fmt.Fprintf(os.Stderr, "fakerestic: unknown subcommand %q\n", sub)
		os.Exit(2)
	}
}

func loadSnaps(repo string) []snapRecord {
	b, err := os.ReadFile(filepath.Join(repo, "snaps.json"))
	if err != nil {
		return nil
	}
	var snaps []snapRecord
	if json.Unmarshal(b, &snaps) != nil {
		return nil
	}
	return snaps
}

func saveSnaps(repo string, snaps []snapRecord) error {
	b, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(repo, "snaps.json"), b, 0o600)
}
