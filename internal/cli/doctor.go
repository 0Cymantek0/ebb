// cmdDoctor implements `ebb doctor` (Foundation §17.1): report
// supported capabilities and configuration problems; no automatic
// system repair. Every check is pass/warn/fail. Only a missing restic
// binary is a HARD prerequisite (exit 2); every other degradation is an
// honest warn — including platform capability gaps such as the Restart
// Manager or named-stream enumeration outside Windows/NTFS.

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/platform"
	"ebb/internal/vault"
)

// doctorCheck is one capability/configuration observation.
type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail
	Detail string `json:"detail,omitempty"`
}

// doctorDetails is the --json payload of the doctor command.
type doctorDetails struct {
	Checks []doctorCheck `json:"checks"`
}

// toolTimeout bounds each version probe subprocess.
const toolTimeout = 15 * time.Second

func cmdDoctor(args []string, streams Streams) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(streams.Err, "ebb doctor: takes no arguments (got %q)\n", fs.Arg(0))
		return ExitUsage
	}

	checks := runDoctorChecks()

	env := newEnvelope("doctor", "ok")
	env.Details = doctorDetails{Checks: checks}
	hardFail := false
	var human bytes.Buffer
	human.WriteString("ebb doctor:\n")
	for _, c := range checks {
		fmt.Fprintf(&human, "  %s: %s", c.Name, c.Status)
		if c.Detail != "" {
			fmt.Fprintf(&human, " — %s", c.Detail)
		}
		human.WriteByte('\n')
		if c.Status == "fail" && c.Name == "restic" {
			hardFail = true
		}
	}
	if hardFail {
		env.Outcome = "fail"
		env.Errors = []string{"doctor: hard prerequisite missing: restic not found on PATH"}
	}
	emit(env, *jsonOut, streams, human.String())
	if hardFail {
		return ExitUsage
	}
	return ExitOK
}

// runDoctorChecks executes the capability probes against disposable
// temp fixtures. Order is stable and matches the human report.
func runDoctorChecks() []doctorCheck {
	var checks []doctorCheck

	// restic: the one hard prerequisite (capture backend).
	if _, err := exec.LookPath("restic"); err != nil {
		checks = append(checks, doctorCheck{Name: "restic", Status: "fail",
			Detail: "not found on PATH (hard prerequisite for capture)"})
	} else if v, err := toolVersion("restic", "version"); err != nil {
		checks = append(checks, doctorCheck{Name: "restic", Status: "warn",
			Detail: "found but `restic version` failed: " + err.Error()})
	} else if v == ResticTarget {
		checks = append(checks, doctorCheck{Name: "restic", Status: "pass",
			Detail: "restic " + v + " matches the conformance target"})
	} else {
		checks = append(checks, doctorCheck{Name: "restic", Status: "warn",
			Detail: "restic " + v + " found; conformance target is " + ResticTarget})
	}

	// git: observation adapter backend; absence degrades inspect to
	// warnings, so it is a warn, never a fail.
	if _, err := exec.LookPath("git"); err != nil {
		checks = append(checks, doctorCheck{Name: "git", Status: "warn",
			Detail: "not found on PATH; git observations will be unavailable"})
	} else if v, err := toolVersion("git", "--version"); err != nil {
		checks = append(checks, doctorCheck{Name: "git", Status: "warn",
			Detail: "found but `git --version` failed: " + err.Error()})
	} else {
		checks = append(checks, doctorCheck{Name: "git", Status: "pass",
			Detail: "git " + v + " (observation recipe validated per version, D004)"})
	}

	// Disposable fixture root for the remaining probes.
	dir, err := os.MkdirTemp("", "ebb-doctor-")
	if err != nil {
		return append(checks, doctorCheck{Name: "platform-probe", Status: "warn",
			Detail: "temp dir unavailable: " + err.Error()})
	}
	defer os.RemoveAll(dir)

	probe := platform.New()

	// Platform probe: identity round trip on a temp file (stable across
	// rename — the domain contract RootIdentity encodes).
	idFile := filepath.Join(dir, "identity.txt")
	if err := os.WriteFile(idFile, []byte("ebb"), 0o644); err != nil {
		checks = append(checks, doctorCheck{Name: "platform-probe", Status: "warn",
			Detail: "cannot create probe file: " + err.Error()})
	} else if id1, err := probe.RootIdentity(idFile); err != nil || id1.VolumeID == "" || id1.FileID == "" {
		checks = append(checks, doctorCheck{Name: "platform-probe", Status: "warn",
			Detail: "root identity unavailable for a regular file"})
	} else {
		renamed := filepath.Join(dir, "identity-renamed.txt")
		if err := os.Rename(idFile, renamed); err != nil {
			checks = append(checks, doctorCheck{Name: "platform-probe", Status: "warn",
				Detail: "rename probe failed: " + err.Error()})
		} else if id2, err := probe.RootIdentity(renamed); err != nil || id2 != id1 {
			checks = append(checks, doctorCheck{Name: "platform-probe", Status: "warn",
				Detail: "file identity not stable across rename (got " + id1.String() + " then " + id2.String() + ")"})
		} else {
			checks = append(checks, doctorCheck{Name: "platform-probe", Status: "pass",
				Detail: "file identity stable across rename (volume " + id1.VolumeID + ")"})
		}
	}

	// Volume usage observable.
	if usage, err := probe.VolumeUsage(dir); err != nil || usage.Total <= 0 {
		checks = append(checks, doctorCheck{Name: "volume-usage", Status: "warn",
			Detail: "volume usage not observable for the temp fixture"})
	} else {
		checks = append(checks, doctorCheck{Name: "volume-usage", Status: "pass",
			Detail: HumanBytes(usage.FreeToCaller) + " available to caller, " +
				HumanBytes(usage.VolumeFree) + " free, " + HumanBytes(usage.Total) + " total"})
	}

	// Writer inspector: Restart Manager on Windows. Cheap self-held-file
	// probe — the inspector must list the process holding the file open
	// (this one). Diagnostics only; never an authorization input (§4.4).
	wi, err := platform.NewWriterInspector()
	if err != nil || errors.Is(err, platform.ErrUnsupported) {
		checks = append(checks, doctorCheck{Name: "writers", Status: "warn",
			Detail: "writer inspection not supported on this platform"})
	} else {
		held := filepath.Join(dir, "held.txt")
		f, ferr := os.OpenFile(held, os.O_CREATE|os.O_RDWR, 0o644)
		if ferr != nil {
			checks = append(checks, doctorCheck{Name: "writers", Status: "warn",
				Detail: "cannot create self-held file: " + ferr.Error()})
		} else {
			self := uint32(os.Getpid())
			writers, werr := wi.InspectWriters([]string{held})
			f.Close()
			switch {
			case werr != nil:
				checks = append(checks, doctorCheck{Name: "writers", Status: "warn",
					Detail: "inspection failed: " + werr.Error()})
			case containsPID(writers, self):
				src := "restart-manager"
				if len(writers) > 0 && writers[0].Source != "" {
					src = writers[0].Source
				}
				checks = append(checks, doctorCheck{Name: "writers", Status: "pass",
					Detail: "listed the self-held file's holder via " + src})
			default:
				checks = append(checks, doctorCheck{Name: "writers", Status: "warn",
					Detail: "no writer reported for a file this process holds open"})
			}
		}
	}

	// Streams enumeration: create a named data stream on a temp file and
	// verify the probe lists it. Outside NTFS this is a capability gap
	// reported as warn, never guessed around.
	streamFile := filepath.Join(dir, "streams.txt")
	streamSeen := false
	if err := os.WriteFile(streamFile, []byte("default stream\n"), 0o644); err == nil {
		if s, serr := os.OpenFile(streamFile+":ebbdoctor", os.O_CREATE|os.O_WRONLY, 0o644); serr == nil {
			_, _ = s.WriteString("named stream\n")
			s.Close()
			if facts, perr := probe.ProbeFile(streamFile); perr == nil {
				for _, st := range facts.Streams {
					if st.Name == "ebbdoctor" {
						streamSeen = true
					}
				}
			}
		}
	}
	if streamSeen {
		checks = append(checks, doctorCheck{Name: "streams", Status: "pass",
			Detail: "named data streams enumerated (NTFS ADS)"})
	} else {
		checks = append(checks, doctorCheck{Name: "streams", Status: "warn",
			Detail: "named-stream enumeration unavailable on this platform/filesystem (honest v1 gap)"})
	}

	// Config dir: the same authority the session uses (EBB_STATE_DIR
	// override, else os.UserConfigDir()/ebb), created if absent.
	if cfgDir, err := vault.DefaultConfigDir(); err != nil {
		checks = append(checks, doctorCheck{Name: "config-dir", Status: "warn",
			Detail: "resolve config dir: " + err.Error()})
	} else {
		probeFile := filepath.Join(cfgDir, ".doctor-probe")
		if err := os.MkdirAll(cfgDir, 0o755); err != nil {
			checks = append(checks, doctorCheck{Name: "config-dir", Status: "warn",
				Detail: "cannot create " + cfgDir + ": " + err.Error()})
		} else if err := os.WriteFile(probeFile, []byte("w"), 0o600); err != nil {
			checks = append(checks, doctorCheck{Name: "config-dir", Status: "warn",
				Detail: "not writable: " + cfgDir})
		} else {
			_ = os.Remove(probeFile)
			checks = append(checks, doctorCheck{Name: "config-dir", Status: "pass",
				Detail: "writable: " + cfgDir})
		}
		// Catalog vs vault registry (cheap local reads only — no backend
		// calls, no unlock): a registered vault whose catalog is missing,
		// unreadable or empty is the F39 signature (the catalog was lost
		// or corrupt while the vault and its secret remain). Doctor only
		// reports; the rebuild command is the user's explicit action.
		checks = append(checks, catalogCheck(cfgDir))
	}

	return checks
}

// catalogCheck compares vaults.json registrations with the catalog
// (Foundation §11.5). Fresh installations legitimately hold a registered
// vault and an empty catalog, so the warn wording names the loss
// hypothesis explicitly instead of asserting one.
func catalogCheck(cfgDir string) doctorCheck {
	vaults, verr := vault.New(filepath.Join(cfgDir, vault.RegistryFile)).List()
	if verr != nil {
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: "vault registry unreadable: " + verr.Error()}
	}
	catFile := filepath.Join(cfgDir, vault.CatalogFile)
	fi, serr := os.Stat(catFile)
	if serr != nil && !errors.Is(serr, os.ErrNotExist) {
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: "cannot stat " + catFile + ": " + serr.Error()}
	}
	if errors.Is(serr, os.ErrNotExist) || fi.Size() == 0 {
		if len(vaults) == 0 {
			return doctorCheck{Name: "catalog", Status: "pass",
				Detail: "no catalog yet (no vault enrolled; it is created by the first command)"}
		}
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: fmt.Sprintf("catalog missing/empty while %d vault(s) are registered — if workspaces were captured on this machine, the catalog was lost or corrupt; rebuild with `ebb init --rebuild-catalog`", len(vaults))}
	}
	// The file exists and is non-empty: open it read-path-only to count
	// rows (a zero-byte file is a valid empty SQLite db, hence the guard
	// above; opening an existing file applies pending migrations only).
	cat, oerr := catalog.Open(catFile)
	if oerr != nil {
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: fmt.Sprintf("catalog %s is unreadable/corrupt (%v); if a vault holds captured workspaces, rebuild with `ebb init --rebuild-catalog`", catFile, oerr)}
	}
	defer cat.Close()
	ws, snaps, qerr := cat.Counts()
	if qerr != nil {
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: fmt.Sprintf("catalog %s did not answer a row count (%v); it may be corrupt — `ebb init --rebuild-catalog` can rebuild from the vault", catFile, qerr)}
	}
	if ws == 0 && snaps == 0 && len(vaults) > 0 {
		return doctorCheck{Name: "catalog", Status: "warn",
			Detail: fmt.Sprintf("catalog holds no workspaces while %d vault(s) are registered — if workspaces were captured on this machine, the catalog was lost; rebuild with `ebb init --rebuild-catalog`", len(vaults))}
	}
	return doctorCheck{Name: "catalog", Status: "pass",
		Detail: fmt.Sprintf("%d workspace(s), %d snapshot(s)", ws, snaps)}
}

// toolVersion runs `<bin> <args...>` and returns the first
// version-shaped token of the first output line ("restic 0.19.1 ..."
// -> "0.19.1"; "git version 2.49.0 ..." -> "2.49.0", where the literal
// word "version" must be skipped).
func toolVersion(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", err
	}
	first := strings.SplitN(strings.TrimSpace(buf.String()), "\n", 2)[0]
	for _, f := range strings.Fields(first) {
		if f != "" && f[0] >= '0' && f[0] <= '9' {
			return f, nil
		}
	}
	return "", fmt.Errorf("unrecognized %s output %q", bin, first)
}

func containsPID(writers []platform.Writer, pid uint32) bool {
	for _, w := range writers {
		if w.PID == pid {
			return true
		}
	}
	return false
}
