// Package freezer implements the Freeze-to-Vault cold-storage pipeline
// (Decisions D040 tier 3, product plan §11.7C): it streams `docker save`
// DIRECTLY into a restic `backup --stdin` with zero bytes staged on disk,
// hashes the stream in flight (io.TeeReader SHA-256), records the durable
// catalog row, and proves the capture by an independent `restic dump`
// readback compared against the recorded digest (Foundation §11.4: a
// successful subprocess exit is not proof of retained data).
//
// Subprocess discipline (mirroring internal/storage/restic): fixed argv,
// never a shell, context-bounded, secrets only through the vault
// passfile — the freezer never sees a password and never puts one in
// argv. The docker side is deliberately NOT an adapter import (D040's
// parallel docker engine lands elsewhere): the freezer takes a docker
// BINARY PATH plus fixed argv; the EBB_TEST_DOCKER_BIN environment
// variable overrides the lookup for tests, the same seam style as
// EBB_TEST_RESTIC_BIN.
//
// Destructive authority: nothing here removes anything from the docker
// daemon on its own. RemoveFromDaemon exists only for the CLI to call
// AFTER a verified freeze AND a separate explicit user confirmation, and
// the catalog refuses to record a removal for an unverified row.
package freezer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// probeTimeout bounds the `docker version` connectivity check (and every
// other bounded docker call). The freeze/restore streams themselves ride
// the caller's context — their duration is data-dependent, not a probe.
const probeTimeout = 5 * time.Second

// saveGraceKill bounds how long a `docker save` producer may outlive its
// consumer before the teardown kills it: closing the pipe normally fails
// the producer with a broken-pipe write long before this fires; the
// timer exists so a producer that IGNORES the closed pipe can never hang
// the freezer (no orphan processes, no leaked handles).
const saveGraceKill = 10 * time.Second

// EnvDockerBin is the test seam for the docker binary path (the same
// discipline as EBB_TEST_RESTIC_BIN): when set, New resolves it instead
// of PATH lookup.
const EnvDockerBin = "EBB_TEST_DOCKER_BIN"

// VaultStore is the restic surface the freezer needs: one streaming
// stdin capture and one streaming single-blob readback. It is satisfied
// by *resticstore.Store; the domain.SnapshotStore interface is frozen
// (D007 seam discipline), so the freezer names its own narrow consumer
// interface instead of widening the domain contract.
type VaultStore interface {
	BackupStdin(ctx context.Context, repoDir, passfile, filename string, src io.Reader, tags map[string]string) (domain.SnapshotRef, error)
	DumpBlob(ctx context.Context, repoDir, passfile, snapID, filename string) (io.ReadCloser, error)
}

// Freezer executes the docker side of the pipeline against one resolved
// docker binary and one vault store. All methods are safe for serial
// use by the CLI; each subprocess is context-bounded.
type Freezer struct {
	dockerBin string
	store     VaultStore
	// testSeam records that New resolved the docker binary through the
	// EBB_TEST_DOCKER_BIN seam. Only then does dockerEnv forward the
	// fake-binary control variable (FAKE_BIN_DIR): a test seam must never
	// ride the production env surface.
	testSeam bool
}

// New resolves the docker binary ("" means PATH "docker"; the
// EBB_TEST_DOCKER_BIN seam wins when set) and binds the vault store. A
// bare name is resolved through PATH BEFORE any absolutization —
// absolutizing "docker" directly would point at <cwd>\docker (the same
// trap RealDeps documents for the restic binary). A docker binary that
// cannot be resolved is a typed connectivity error surfaced by Probe,
// not a construction failure.
func New(dockerBin string, store VaultStore) (*Freezer, error) {
	if store == nil {
		return nil, errors.New("freezer: vault store is required")
	}
	seam := os.Getenv(EnvDockerBin)
	if seam != "" {
		dockerBin = seam
	}
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if filepath.IsAbs(dockerBin) {
		if abs, err := filepath.Abs(dockerBin); err == nil {
			dockerBin = abs // normalize separators/Case only
		}
	} else if resolved, err := exec.LookPath(dockerBin); err == nil {
		dockerBin = resolved
	}
	return &Freezer{dockerBin: dockerBin, store: store, testSeam: seam != ""}, nil
}

// ImageInfo is what `docker image inspect` truthfully told us about one
// image. Size is the daemon's own logical accounting (an estimate of
// what freezing may move, never a promise).
type ImageInfo struct {
	ID       string   `json:"id"`
	Size     int64    `json:"size"`
	RepoTags []string `json:"repo_tags"`
}

// FreezeRequest addresses one freeze: the image, the vault location and
// the catalog that receives the durable row. VaultID must already be a
// registered vault row (the CLI registers it beside the registry vault,
// like the lifecycle capture path does).
type FreezeRequest struct {
	ImageID  string
	RepoDir  string
	Passfile string
	VaultID  domain.VaultID
	Cat      *catalog.Catalog
}

// FreezeResult reports the completed (or retained-unverified) freeze.
type FreezeResult struct {
	Info  ImageInfo
	Entry catalog.DockerImage
	Ref   domain.SnapshotRef
	// Verified is true only when the independent readback digest matched
	// AND the verified_at stamp was durably recorded.
	Verified bool
}

// RestoreResult reports a completed restore into the docker daemon.
type RestoreResult struct {
	Bytes      int64
	SHA256     string
	LoadOutput string // first line of `docker load` output (digest report)
}

// ---- typed errors --------------------------------------------------------

// ErrDockerUnreachable wraps a failed `docker version` probe: the daemon
// (or the CLI) is not usable, so nothing at all happened yet.
type ErrDockerUnreachable struct {
	Underlying error
}

func (e *ErrDockerUnreachable) Error() string {
	return fmt.Sprintf("freezer: docker is not reachable (`docker version` failed: %v)", e.Underlying)
}

func (e *ErrDockerUnreachable) Unwrap() error { return e.Underlying }

// ErrImageUnknown reports that `docker image inspect` does not know the
// image — an argument mistake, nothing ran.
type ErrImageUnknown struct {
	ImageID string
	Detail  string
}

func (e *ErrImageUnknown) Error() string {
	return fmt.Sprintf("freezer: docker does not know image %q (%s)", e.ImageID, e.Detail)
}

// ErrUnverifiedFreeze reports a refused daemon-side removal: the freeze
// row has no verified_at evidence, so no removal authority exists.
type ErrUnverifiedFreeze struct {
	EntryID domain.ID
}

func (e *ErrUnverifiedFreeze) Error() string {
	return fmt.Sprintf("freezer: freeze entry %s is UNVERIFIED; the daemon image can only be removed after a readback-verified freeze", e.EntryID)
}

// ErrHashMismatch reports that the vault's bytes did not read back to
// the recorded digest — Foundation §11.4's independent-oracle failure.
// It is constructed as a StoreErrIntegrity StoreError so the CLI's
// existing classification maps it to the capture/verify exit code.
type ErrHashMismatch struct {
	SnapshotID string
	Filename   string
	WantDigest string
	GotDigest  string
	WantBytes  int64
	GotBytes   int64
}

func (e *ErrHashMismatch) Error() string {
	return fmt.Sprintf(
		"freezer: readback verification FAILED for %s/%s: vault returned digest %s (%d bytes), the freeze recorded %s (%d bytes); the entry stays unverified and pinned, nothing was removed, and the snapshot is retained (Foundation §11.3/§11.4)",
		e.SnapshotID, e.Filename, e.GotDigest, e.GotBytes, e.WantDigest, e.WantBytes)
}

// ErrHostileImageID reports an image id of untrusted origin — the
// daemon's own inspect echo, or a stored catalog row — that failed its
// validation contract. Daemon-returned data is attacker-influenceable
// and the id later reaches `docker save`/`rmi` argv (flag injection
// through a leading "-" is real even without a shell), so anything
// outside the contract is refused before a single subprocess runs.
type ErrHostileImageID struct {
	ImageID string
	Detail  string
}

func (e *ErrHostileImageID) Error() string {
	return fmt.Sprintf(
		"freezer: refusing image id %q: %s — daemon-returned data is untrusted; nothing was streamed, loaded, or removed",
		e.ImageID, e.Detail)
}

// ErrRestoreDivergence reports that the bytes actually streamed into
// `docker load` (hashed as they loaded) diverged from the frozen
// entry's recorded digest/byte count that the verify pass had just
// proven — the vault answered the two dumps differently. The load
// already ran, so the daemon may hold unverified bytes: the divergence
// is named and the restore fails, never reports "verified".
type ErrRestoreDivergence struct {
	SnapshotID string
	Filename   string
	WantDigest string
	GotDigest  string
	WantBytes  int64
	GotBytes   int64
}

func (e *ErrRestoreDivergence) Error() string {
	diverged := "digest and byte count"
	if e.GotDigest == e.WantDigest {
		diverged = "byte count"
	} else if e.GotBytes == e.WantBytes {
		diverged = "digest"
	}
	return fmt.Sprintf(
		"freezer: restore of %s/%s FAILED the load-time check: the %s of the bytes streamed into docker load diverged from the verified readback (the load pass received digest %s over %d bytes; the freeze recorded %s over %d bytes) — treat the loaded image as UNVERIFIED and rerun the restore",
		e.SnapshotID, e.Filename, diverged, e.GotDigest, e.GotBytes, e.WantDigest, e.WantBytes)
}

// ---- docker subprocess plumbing ------------------------------------------

// dockerEnv builds the child environment for every docker subprocess: a
// minimal OS substrate (the restic adapter's discipline) plus EVERY
// inherited DOCKER_* variable — the same sanctioned routing family the
// analyse engine's docker adapter forwards (host/context AND
// cert/TLS configuration, so a DOCKER_CERT_PATH endpoint gets analyse
// and freeze agreeing), while hostile inherited values of anything else
// cannot reach the child. The FAKE_BIN_DIR fake-binary control variable
// rides along ONLY when New resolved the binary through the
// EBB_TEST_DOCKER_BIN seam (f.testSeam): a test seam must never ride
// the production env surface.
const envFakeBinDir = "FAKE_BIN_DIR"

func (f *Freezer) dockerEnv() []string {
	var substrate []string
	if runtime.GOOS == "windows" {
		substrate = []string{"PATH", "SYSTEMROOT", "COMSPEC", "WINDIR", "TEMP", "TMP", "PATHEXT",
			"LOCALAPPDATA", "APPDATA", "USERPROFILE"}
	} else {
		substrate = []string{"PATH", "TMPDIR", "HOME", "LANG", "LC_ALL", "TZ"}
	}
	inherited := os.Environ()
	out := make([]string, 0, len(substrate)+8)
	for _, want := range substrate {
		for _, kv := range inherited {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			if envKeyEqual(kv[:eq], want) {
				out = append(out, kv)
				break // first spelling wins
			}
		}
	}
	// The DOCKER_* routing family passes through wholesale (prefix rule),
	// exactly like the docker adapter: host/context AND cert/TLS
	// configuration must reach the client.
	for _, kv := range inherited {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		if envKeyHasPrefix(kv[:eq], dockerEnvPrefix) {
			out = append(out, kv)
		}
	}
	// The fake-binary control variable rides along only in seam mode.
	if f.testSeam {
		for _, kv := range inherited {
			eq := strings.IndexByte(kv, '=')
			if eq > 0 && envKeyEqual(kv[:eq], envFakeBinDir) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// dockerEnvPrefix is the passthrough family every inherited variable of
// which reaches the docker child (host/context/cert/TLS routing).
const dockerEnvPrefix = "DOCKER_"

// envKeyEqual compares an inherited variable name. Windows environment
// lookup is case-insensitive, so the comparison is too.
func envKeyEqual(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// envKeyHasPrefix is the prefix form for the DOCKER_* passthrough
// family, case-insensitive on Windows like the exact form. The docker
// adapter's rule, reimplemented locally — the packages stay decoupled.
func envKeyHasPrefix(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name[:len(prefix)], prefix)
	}
	return name[:len(prefix)] == prefix
}

// runDocker executes one bounded docker command and captures both
// streams. Non-zero exits come back as a plain error carrying the
// excerpted output (callers wrap in their own typed errors).
func (f *Freezer) runDocker(ctx context.Context, timeout time.Duration, argv ...string) (stdout, stderr []byte, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, f.dockerBin, argv...)
	cmd.Env = f.dockerEnv()
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 10 * time.Second
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), errb.Bytes(), fmt.Errorf("docker %s: %w", argv[0], ctx.Err())
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return out.Bytes(), errb.Bytes(), fmt.Errorf("docker %s exited %d\nstdout:\n%s\nstderr:\n%s",
				strings.Join(argv, " "), cmd.ProcessState.ExitCode(),
				excerpt(out.Bytes()), excerpt(errb.Bytes()))
		}
		return out.Bytes(), errb.Bytes(), fmt.Errorf("docker %s: %w", argv[0], runErr)
	}
	return out.Bytes(), errb.Bytes(), nil
}

func excerpt(b []byte) string {
	if len(b) > 2048 {
		return "…[truncated] " + string(b[len(b)-2048:])
	}
	return string(b)
}

// Probe verifies the docker CLI resolves and the daemon answers, within
// probeTimeout. It is the gate every freeze/restore flow runs FIRST —
// before any prompt, so an unreachable daemon is a cheap honest block.
func (f *Freezer) Probe(ctx context.Context) error {
	if _, err := exec.LookPath(f.dockerBin); err != nil {
		return &ErrDockerUnreachable{Underlying: fmt.Errorf("docker binary %q not found: %w", f.dockerBin, err)}
	}
	_, _, err := f.runDocker(ctx, probeTimeout, "version")
	if err != nil {
		return &ErrDockerUnreachable{Underlying: err}
	}
	return nil
}

// Inspect returns the daemon's own record for one image. Unknown images
// are a typed argument mistake.
func (f *Freezer) Inspect(ctx context.Context, imageID string) (ImageInfo, error) {
	if err := ValidateImageID(imageID); err != nil {
		return ImageInfo{}, err
	}
	stdout, _, err := f.runDocker(ctx, probeTimeout, "image", "inspect", imageID)
	if err != nil {
		return ImageInfo{}, &ErrImageUnknown{ImageID: imageID, Detail: "inspect failed: " + err.Error()}
	}
	var docs []struct {
		ID       string   `json:"Id"`
		Size     int64    `json:"Size"`
		RepoTags []string `json:"RepoTags"`
	}
	if jerr := json.Unmarshal(stdout, &docs); jerr != nil || len(docs) == 0 {
		return ImageInfo{}, &ErrImageUnknown{ImageID: imageID,
			Detail: fmt.Sprintf("unparsable inspect output (%v): %s", jerr, excerpt(stdout))}
	}
	info := ImageInfo{ID: docs[0].ID, Size: docs[0].Size, RepoTags: docs[0].RepoTags}
	if info.ID == "" {
		// Daemon records may omit Id for short ids; the argument spelling
		// is the truth then — still gated by the argv-safety re-check,
		// because it too reaches `docker save` argv.
		if verr := validateStoredImageID(imageID); verr != nil {
			return ImageInfo{}, &ErrHostileImageID{ImageID: imageID, Detail: verr.Error()}
		}
		info.ID = imageID
	} else if verr := validateDaemonImageID(info.ID); verr != nil {
		// The daemon's echo is attacker-influenceable data that becomes
		// `docker save` argv and the durable entry.ImageID (later `rmi`
		// argv): it must be a content-addressed docker id, nothing looser.
		return ImageInfo{}, &ErrHostileImageID{ImageID: info.ID,
			Detail: "the daemon's inspect record echoed an id that is not a content-addressed docker image id (" + verr.Error() + ")"}
	}
	return info, nil
}

// ValidateImageID enforces the client-side spelling contract for image
// ids and tags: non-empty, no whitespace/NUL/shell metacharacters, one
// reasonable length. It is deliberately conservative — argv is fixed
// and never shell-evaluated, but a tight charset keeps typos honest.
func ValidateImageID(imageID string) error {
	if imageID == "" {
		return errors.New("freezer: image id must not be empty")
	}
	if len(imageID) > 255 {
		return errors.New("freezer: image id exceeds 255 characters")
	}
	for _, c := range imageID {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ':' || c == '.' || c == '_' || c == '-' || c == '/':
		default:
			return fmt.Errorf("freezer: image id %q contains a character outside [A-Za-z0-9:._/-]", imageID)
		}
	}
	return nil
}

// validateDaemonImageID enforces the STRICT contract for a daemon-echoed
// image id (docker image inspect's Id field): an optional "sha256:"
// prefix followed by exactly 64 hex characters. Real daemons always
// answer in this form; anything else is hostile or broken daemon data
// that must never reach `docker save`/`rmi` argv (a leading "-" hijacks
// flag parsing even without a shell, and any looser charset would let
// the daemon choose what the freezer executes).
func validateDaemonImageID(id string) error {
	hexPart := strings.TrimPrefix(id, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("want an optional sha256: prefix plus 64 hex characters, got %d after the prefix", len(hexPart))
	}
	for _, c := range hexPart {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return fmt.Errorf("character %q is outside hex", string(c))
		}
	}
	return nil
}

// validateStoredImageID re-checks an image id that arrived from durable
// storage (entry.ImageID) before it reaches `docker rmi` argv: the
// client-side spelling contract plus the leading-dash refusal (a
// corrupted or hostile row must never execute).
func validateStoredImageID(id string) error {
	if err := ValidateImageID(id); err != nil {
		return err
	}
	if strings.HasPrefix(id, "-") {
		return errors.New("freezer: a leading '-' can hijack docker flag parsing")
	}
	return nil
}

// FilenameFor derives the deterministic --stdin-filename of one image
// inside its restic snapshot (a single clean path segment; characters
// outside the restic tag charset fold to '_').
func FilenameFor(imageID string) string {
	var b strings.Builder
	b.WriteString("docker-image-")
	for _, c := range imageID {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.' || c == '_' || c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	b.WriteString(".tar")
	return b.String()
}

// ---- freeze ----------------------------------------------------------------

// Freeze runs the whole pipeline for one image: inspect, stream
// `docker save` into `restic backup --stdin` while hashing in flight,
// record the durable row, then verify by independent readback. On ANY
// failure nothing is removed from the daemon, whatever restic stored
// stays retained (§11.3 — Ebb never auto-forgets), and a recorded row
// stays unverified and pinned.
func (f *Freezer) Freeze(ctx context.Context, req FreezeRequest) (FreezeResult, error) {
	if req.Cat == nil {
		return FreezeResult{}, errors.New("freezer: FreezeRequest.Cat is required")
	}
	if req.RepoDir == "" || req.Passfile == "" {
		return FreezeResult{}, errors.New("freezer: FreezeRequest needs the vault repo dir and passfile")
	}
	info, err := f.Inspect(ctx, req.ImageID)
	if err != nil {
		return FreezeResult{}, err
	}

	filename := FilenameFor(info.ID)
	tags := map[string]string{
		"op":    "freeze",
		"image": sanitizeTagToken(info.ID),
	}

	// `docker save` — the producer. NOT bound to the context: the
	// teardown below owns its lifetime (kill the consumer, close the
	// pipe, the producer dies of the broken pipe, bounded by a grace
	// kill), which keeps the producer's exit observable even on
	// cancellation.
	saveCmd := exec.Command(f.dockerBin, "save", info.ID)
	saveCmd.Env = f.dockerEnv()
	pr, pw, perr := os.Pipe()
	if perr != nil {
		return FreezeResult{}, fmt.Errorf("freezer: save pipe: %w", perr)
	}
	saveCmd.Stdout = pw
	var saveStderr bytes.Buffer
	saveCmd.Stderr = &saveStderr
	if serr := saveCmd.Start(); serr != nil {
		pr.Close()
		pw.Close()
		return FreezeResult{}, fmt.Errorf("freezer: start docker save: %w", serr)
	}
	// The child owns the write end now; the parent's copy must go.
	pw.Close()

	// In-flight hashing: everything restic drinks passes the digest and
	// the byte counter (io.TeeReader, Foundation §11.4 readback basis).
	hash := sha256.New()
	count := &countingWriter{}
	tee := io.TeeReader(pr, io.MultiWriter(hash, count))

	ref, berr := f.store.BackupStdin(ctx, req.RepoDir, req.Passfile, filename, tee, tags)

	// Teardown of the producer regardless of outcome: close the read end
	// (a still-writing producer fails with a broken-pipe write), wait
	// bounded by the grace kill, and surface a non-zero save exit — a
	// tar that died mid-stream is not a capture even if restic saw a
	// clean EOF (the §11.4 both-gates discipline applied at the pipe).
	pr.Close()
	kill := time.AfterFunc(saveGraceKill, func() { _ = saveCmd.Process.Kill() })
	saveWaitErr := saveCmd.Wait()
	kill.Stop()

	switch {
	case berr != nil:
		return FreezeResult{Info: info}, fmt.Errorf("freezer: freeze of %s failed: %w%s",
			info.ID, berr, saveContext(saveWaitErr, saveStderr.Bytes()))
	case ctx.Err() != nil:
		return FreezeResult{Info: info}, fmt.Errorf("freezer: freeze of %s interrupted: %w%s",
			info.ID, ctx.Err(), saveContext(saveWaitErr, saveStderr.Bytes()))
	case saveWaitErr != nil:
		// restic exited 0 on a clean early EOF but the producer failed:
		// the stored blob is a truncated prefix. It stays retained; the
		// id is named so nothing ever treats it as a capture.
		return FreezeResult{Info: info}, &domain.StoreError{Class: domain.StoreErrSource, Err: fmt.Errorf(
			"freezer: docker save exited abnormally while restic saw a clean end of stream — the stored snapshot %s holds a TRUNCATED prefix and must never be used as a capture (retained per §11.3; nothing was removed)\nsave error: %v\nsave stderr:\n%s",
			ref.BackendID, saveWaitErr, excerpt(saveStderr.Bytes()))}
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	entryID, rerr := req.Cat.RecordDockerImage(catalog.DockerImage{
		ImageID:    info.ID,
		VaultID:    req.VaultID,
		SnapshotID: ref.BackendID,
		Filename:   filename,
		SHA256:     digest,
		Bytes:      count.n,
	})
	if rerr != nil {
		return FreezeResult{Info: info, Ref: ref}, fmt.Errorf(
			"freezer: freeze of %s streamed and hashed successfully (snapshot %s, digest %s, %d bytes) but the durable catalog row failed: %w — the snapshot stays retained; rerunning the freeze records a fresh entry",
			info.ID, ref.BackendID, digest, count.n, rerr)
	}
	entry, _ := req.Cat.GetDockerImage(entryID)
	res := FreezeResult{Info: info, Entry: entry, Ref: ref}

	// Independent readback: dump the blob and compare digest AND byte
	// count against what the tee observed (§11.4).
	if _, _, verr := f.VerifyEntry(ctx, entry, req.RepoDir, req.Passfile); verr != nil {
		return res, verr
	}
	if merr := req.Cat.MarkDockerImageVerified(entryID, domain.FormatTime(time.Now().UTC())); merr != nil {
		return res, fmt.Errorf("freezer: freeze of %s verified but recording the verified_at stamp failed: %w (the row stays unverified and pinned; the image was NOT removed)", info.ID, merr)
	}
	entry, _ = req.Cat.GetDockerImage(entryID)
	res.Entry = entry
	res.Verified = true
	return res, nil
}

// saveContext appends the producer's outcome to a failure message when
// it carries extra evidence.
func saveContext(waitErr error, stderr []byte) string {
	if waitErr == nil {
		return ""
	}
	return fmt.Sprintf(" (additionally: docker save exited abnormally: %v; stderr: %s)",
		waitErr, excerpt(stderr))
}

// VerifyEntry streams the vault's copy of one freeze entry back through
// a SHA-256 and compares it with the recorded digest and byte count —
// the independent-oracle readback of Foundation §11.4 (the recording
// path and the proving path share no code beyond the digest itself).
func (f *Freezer) VerifyEntry(ctx context.Context, entry catalog.DockerImage, repoDir, passfile string) (digest string, n int64, err error) {
	stream, derr := f.store.DumpBlob(ctx, repoDir, passfile, entry.SnapshotID, entry.Filename)
	if derr != nil {
		return "", 0, derr
	}
	h := sha256.New()
	n, cerr := io.Copy(h, stream)
	if cerr != nil {
		stream.Close()
		return "", 0, fmt.Errorf("freezer: readback of %s/%s failed mid-stream: %w", entry.SnapshotID, entry.Filename, cerr)
	}
	// Close is the producer-exit gate; it must follow a full consumption.
	if clerr := stream.Close(); clerr != nil {
		return "", 0, clerr
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != entry.SHA256 || n != entry.Bytes {
		return got, n, &domain.StoreError{Class: domain.StoreErrIntegrity, Err: &ErrHashMismatch{
			SnapshotID: entry.SnapshotID, Filename: entry.Filename,
			WantDigest: entry.SHA256, GotDigest: got,
			WantBytes: entry.Bytes, GotBytes: n,
		}}
	}
	return got, n, nil
}

// ---- restore ---------------------------------------------------------------

// Restore loads one freeze entry back into the docker daemon in TWO
// passes, both proven: the vault's bytes are first read back and
// verified against the recorded digest (docker load has not even
// started — a mismatch aborts before a single byte reaches the daemon),
// and the second dump streamed into `docker load` is hashed AS it loads
// (io.MultiWriter into the digest and a byte counter) and compared with
// the frozen entry's digest and byte count before success is reported —
// a vault that answers the two dumps differently fails with the
// divergence named, never a "verified" restore. No temp file is ever
// created (low-headroom discipline; §14.1).
func (f *Freezer) Restore(ctx context.Context, entry catalog.DockerImage, repoDir, passfile string) (RestoreResult, error) {
	pass1Digest, pass1Bytes, verr := f.VerifyEntry(ctx, entry, repoDir, passfile)
	if verr != nil {
		return RestoreResult{}, verr
	}

	loadCmd := exec.Command(f.dockerBin, "load")
	loadCmd.Env = f.dockerEnv()
	stdin, lerr := loadCmd.StdinPipe()
	if lerr != nil {
		return RestoreResult{}, fmt.Errorf("freezer: docker load stdin pipe: %w", lerr)
	}
	var loadOut bytes.Buffer
	loadCmd.Stdout = &loadOut
	loadCmd.Stderr = &loadOut
	if serr := loadCmd.Start(); serr != nil {
		return RestoreResult{}, fmt.Errorf("freezer: start docker load: %w", serr)
	}

	stream, derr := f.store.DumpBlob(ctx, repoDir, passfile, entry.SnapshotID, entry.Filename)
	if derr != nil {
		stdin.Close()
		_ = loadCmd.Wait()
		return RestoreResult{}, derr
	}
	// Pass 2 is NOT trusted: every byte docker load drinks is hashed and
	// counted in flight (the same §11.4 discipline as the capture side),
	// and the digest is compared with the frozen entry BEFORE success is
	// reported — RestoreResult.SHA256 always describes the bytes that
	// were actually loaded, never pass-1's.
	loadHash := sha256.New()
	loadCount := &countingWriter{}
	n, copyErr := io.Copy(io.MultiWriter(stdin, loadHash, loadCount), stream)
	closeErr := stdin.Close()
	dumpErr := stream.Close() // producer gates: exit 0 AND fully consumed
	waitErr := loadCmd.Wait()

	switch {
	case copyErr != nil:
		return RestoreResult{}, fmt.Errorf("freezer: streaming %s/%s into docker load failed after %d bytes: %w",
			entry.SnapshotID, entry.Filename, n, copyErr)
	case dumpErr != nil:
		return RestoreResult{}, fmt.Errorf("freezer: docker load consumed %d bytes but the vault readback stream did not close clean (Foundation §11.4): %w", n, dumpErr)
	case closeErr != nil:
		return RestoreResult{}, fmt.Errorf("freezer: closing docker load stdin: %w", closeErr)
	case ctx.Err() != nil:
		return RestoreResult{}, fmt.Errorf("freezer: restore of %s interrupted: %w", entry.ImageID, ctx.Err())
	case waitErr != nil:
		return RestoreResult{}, fmt.Errorf("freezer: docker load failed: %w\noutput:\n%s", waitErr, excerpt(loadOut.Bytes()))
	}
	loadedDigest := hex.EncodeToString(loadHash.Sum(nil))
	if loadedDigest != entry.SHA256 || loadCount.n != entry.Bytes ||
		loadedDigest != pass1Digest || loadCount.n != pass1Bytes {
		// Pass 1 proved digest (== entry.SHA256) moments ago; the load
		// pass received something else. The daemon already drank the
		// divergent bytes, so name them and fail — never "verified".
		return RestoreResult{}, &domain.StoreError{Class: domain.StoreErrIntegrity, Err: &ErrRestoreDivergence{
			SnapshotID: entry.SnapshotID, Filename: entry.Filename,
			WantDigest: entry.SHA256, GotDigest: loadedDigest,
			WantBytes: entry.Bytes, GotBytes: loadCount.n,
		}}
	}
	return RestoreResult{Bytes: loadCount.n, SHA256: loadedDigest, LoadOutput: firstLine(loadOut.Bytes())}, nil
}

// ---- daemon-side removal ----------------------------------------------------

// RemoveFromDaemon removes the image from the docker daemon — the ONLY
// mutating docker operation in the package, reachable exclusively from
// the CLI's separate post-verification confirmation. It refuses
// unverified entries (defense in depth beside the catalog's own
// refusal), re-validates the stored image id before it reaches argv,
// and records the audited removal timestamp on success. The
// rmi-then-mark order is IDEMPOTENTLY RECONCILABLE: when the daemon
// answers "No such image" (typically a previous rmi succeeded but the
// durable mark failed), the removal is treated as already done and the
// audit row is brought in line with daemon reality — every other rmi
// failure stays a real failure. The mark is never written before a
// successful (or already-gone) rmi: that would create the inverse lie.
func (f *Freezer) RemoveFromDaemon(ctx context.Context, entry catalog.DockerImage, cat *catalog.Catalog) error {
	if cat == nil {
		return errors.New("freezer: catalog is required to audit the removal")
	}
	if entry.VerifiedAt == "" {
		return &ErrUnverifiedFreeze{EntryID: entry.ID}
	}
	if entry.DaemonRemovedAt != "" {
		return fmt.Errorf("freezer: daemon image %s was already removed at %s", entry.ImageID, entry.DaemonRemovedAt)
	}
	// The stored id reaches `docker rmi` argv: re-validate it (a
	// corrupted or hostile row must never execute).
	if verr := validateStoredImageID(entry.ImageID); verr != nil {
		return &ErrHostileImageID{ImageID: entry.ImageID,
			Detail: "the stored entry's image id failed the argv-safety re-check: " + verr.Error()}
	}
	_, _, err := f.runDocker(ctx, time.Minute, "rmi", entry.ImageID)
	if err != nil && isNoSuchImageError(err) {
		// The daemon already does not hold the image — the only out-of-
		// sync thing is the audit row. Reconcile: record the mark so the
		// catalog agrees with daemon reality instead of failing forever.
		err = nil
	}
	if err != nil {
		return fmt.Errorf("freezer: docker rmi %s failed (the freeze stays verified and pinned): %w", entry.ImageID, err)
	}
	return cat.MarkDockerImageRemoved(entry.ID, domain.FormatTime(time.Now().UTC()))
}

// isNoSuchImageError recognizes the daemon's "No such image" response
// (case-insensitive: the real client text and test/fake spellings) —
// the one rmi failure that means "already gone", which makes the
// mark-after-rmi order reconcilable instead of a permanent audit lie.
func isNoSuchImageError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such image")
}

// ---- small helpers ----------------------------------------------------------

// countingWriter accumulates the byte count of the in-flight stream.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// sanitizeTagToken folds an image id into the restic tag charset
// ([A-Za-z0-9._-], the adapter's validTagToken).
func sanitizeTagToken(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.' || c == '_' || c == '-':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimRight(line, "\r")
}
