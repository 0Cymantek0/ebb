// Package dockeradapter implements the 7-tier Docker clutter & staleness
// engine (decision D040; product plan §11.7) behind ebb analyse.
//
// Contract (Foundation I11 & §10.4 — zero automated global prunes):
//
//   - The engine NEVER mutates Docker state. Every invocation the runner
//     can spawn is drawn from a fixed observation allowlist (exact argv
//     shapes; `volume inspect` appends only charset-validated volume
//     names), enforced before any process starts. TestNoMutatingArgv is
//     the tripwire.
//   - Every recommendation is a copyable native command; execution stays
//     in the developer's terminal, never in this process.
//   - Degradation is honest: absent binary or unreachable daemon yields
//     Available=false with the reason in Warnings, never a fake report.
//     Partial failures (buildx shape drift, one unparsable JSON line)
//     become warnings, never panics, never silent coverage claims.
//
// Docker is NOT git: there is no repository-owned config to neutralize,
// so the git adapter's two-pass recipe does not apply. The subprocess
// discipline does: constructed minimal environment, no shell, fixed
// argv, both streams captured, per-call context timeout.
package dockeradapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Typed probe failures. Both are degradation facts, not I/O faults:
// callers surface them (Available=false + warning), they never fail a
// whole analyse run.
var (
	// ErrBinaryAbsent: no docker binary was resolved (New was given "").
	ErrBinaryAbsent = errors.New("dockeradapter: docker binary absent")
	// ErrDaemonUnreachable: the CLI ran but the daemon did not answer.
	ErrDaemonUnreachable = errors.New("dockeradapter: docker daemon unreachable")
)

// errNotAllowlisted reports an argv outside the observation allowlist.
var errNotAllowlisted = errors.New("dockeradapter: argv not in observation allowlist")

// errSpawnStart marks a docker process that could not be started at
// all (missing/not-executable binary); Probe maps it to ErrBinaryAbsent.
var errSpawnStart = errors.New("dockeradapter: docker binary failed to start")

// Per-call timeouts. The probe bound is deliberately short (≤5s, per the
// engine contract); buildx du walks the local cache store and is slower.
const (
	probeTimeout        = 5 * time.Second
	commandTimeout      = 30 * time.Second
	buildxTimeout       = 90 * time.Second
	maxParsedRecords    = 5000 // parse bound per collection command
	volumeInspectChunk  = 50   // names per `docker volume inspect` call
	NDJSON              = "--format"
	ndjsonValue         = "json"
	jsonTemplateValue   = "{{json .}}"
	serverVersionFormat = "{{.Server.Version}}"
)

// argvRule is one allowlist entry: a fixed argv prefix plus a bounded
// number of free-form trailing arguments (only `volume inspect` uses
// those; every free argument must satisfy volumeNameRe).
type argvRule struct {
	tokens []string
	free   int
}

// allowedArgv enumerates the exact observation argv shapes the engine may
// ever run. Matching is exact (slices.Equal) for free==0 rules; prefix +
// validated names for volume inspect. Every rule is a pure read. The
// `--format {{json .}}` variants are fallbacks for CLIs predating the
// bare `--format json` NDJSON printer.
var allowedArgv = []argvRule{
	{tokens: []string{"version", "--format", serverVersionFormat}},
	{tokens: []string{"info", "--format", serverVersionFormat}},
	{tokens: []string{"image", "ls", "-a", "--format", ndjsonValue}},
	{tokens: []string{"image", "ls", "-a", "--format", jsonTemplateValue}},
	{tokens: []string{"ps", "-a", "--format", ndjsonValue}},
	{tokens: []string{"ps", "-a", "--format", jsonTemplateValue}},
	{tokens: []string{"volume", "ls", "--format", ndjsonValue}},
	{tokens: []string{"volume", "ls", "--format", jsonTemplateValue}},
	{tokens: []string{"volume", "inspect"}, free: volumeInspectChunk},
	{tokens: []string{"buildx", "du", "--verbose", "--json"}},
	{tokens: []string{"buildx", "du", "--verbose"}},
	{tokens: []string{"system", "df", "--format", ndjsonValue}},
	{tokens: []string{"system", "df", "--format", jsonTemplateValue}},
}

// volumeNameRe validates every free-form argument appended to
// `volume inspect` (volume names: 64-hex anonymous or compose-style
// identifiers). Anything else is refused before a process starts, so no
// injection surface exists even though no shell is involved.
var volumeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func allowlistCheck(args []string) error {
	for _, rule := range allowedArgv {
		if len(rule.tokens) > len(args) {
			continue
		}
		if !equalTokens(rule.tokens, args[:len(rule.tokens)]) {
			continue
		}
		rest := args[len(rule.tokens):]
		if rule.free == 0 {
			if len(rest) == 0 {
				return nil
			}
			continue
		}
		if len(rest) > rule.free {
			continue
		}
		ok := true
		for _, name := range rest {
			if !volumeNameRe.MatchString(name) {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
	}
	return errNotAllowlisted
}

func equalTokens(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- report contract (frozen consumer interface) ---------------------

// DockerTier is one classification tier with its items and the copyable
// native command the developer may run by hand. CopyCommand is set only
// when at least one unshielded item exists — an empty or shield-only
// tier recommends nothing.
type DockerTier struct {
	Tier        int          `json:"tier"`
	Title       string       `json:"title"`
	Items       []DockerItem `json:"items,omitempty"`
	CopyCommand string       `json:"copy_command,omitempty"`
}

// DockerItem is one classified Docker object. A non-empty Shield marks
// a PROTECTED item: it is listed for visibility but never recommended.
type DockerItem struct {
	ID     string `json:"id"`
	Detail string `json:"detail"`
	Shield string `json:"shield,omitempty"`
}

// DockerReport is the full engine result. Available=false means docker
// analysis was honestly not performed (binary absent / daemon down) —
// Warnings carries the reason.
type DockerReport struct {
	Available    bool         `json:"available"`
	Tiers        []DockerTier `json:"tiers,omitempty"`
	HostSlack    int64        `json:"host_slack"`              // bytes (tier 5 measurement)
	SlackCommand string       `json:"slack_command,omitempty"` // tier 5 copyable command
	Warnings     []string     `json:"warnings,omitempty"`
}

// AllocationProbe reports the physical on-disk allocation of one file.
// The Windows implementation reuses internal/platform's
// GetCompressedFileSizeW-backed probe (no duplicated Win32 code); it is
// injected so tests and non-Windows platforms stay honest without
// faking the capability. ok=false means "unobservable", never "zero".
type AllocationProbe interface {
	AllocatedSize(path string) (size int64, ok bool)
}

// Engine is the Docker clutter analysis engine. It is read-only by
// construction: its only effects are docker CLI observation subprocesses
// from the allowlist above. Safe for concurrent use.
type Engine struct {
	bin   string
	alloc AllocationProbe
}

// New returns an engine bound to binPath (resolved by the caller via
// exec.LookPath; "" means "no docker" and yields honest unavailable
// reports). The native allocation probe for Windows host-slack
// measurement is wired automatically; tests replace it through
// NewWithAllocationProbe.
func New(binPath string) *Engine {
	return &Engine{bin: binPath, alloc: defaultAllocationProbe()}
}

// NewWithAllocationProbe is New with an injected physical-allocation
// probe (nil disables host-slack measurement honestly — the same
// degraded path as platforms without the capability).
func NewWithAllocationProbe(binPath string, alloc AllocationProbe) *Engine {
	return &Engine{bin: binPath, alloc: alloc}
}

// Probe verifies daemon connectivity and reports the server version
// capability. It runs `docker version --format '{{.Server.Version}}'`
// with a 5s bound, falling back to `docker info --format` of the same
// field. Typed results: ErrBinaryAbsent when the binary cannot execute,
// ErrDaemonUnreachable when both probes fail; the daemon-down stderr
// excerpt rides along for the report's Warnings.
func (e *Engine) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if e.bin == "" {
		return ErrBinaryAbsent
	}
	out, stderr, rc, err := e.run(ctx, probeTimeout, "version", "--format", serverVersionFormat)
	if parentDone(ctx, err) {
		return ctx.Err()
	}
	if err == nil && rc == 0 && strings.TrimSpace(out) != "" {
		return nil
	}
	if spawnFailed(err) {
		return fmt.Errorf("%w: %s", ErrBinaryAbsent, e.bin)
	}
	detail := firstLine(stderr)
	out2, stderr2, rc2, err2 := e.run(ctx, probeTimeout, "info", "--format", serverVersionFormat)
	if parentDone(ctx, err2) {
		return ctx.Err()
	}
	if err2 == nil && rc2 == 0 && strings.TrimSpace(out2) != "" {
		return nil
	}
	if spawnFailed(err2) {
		return fmt.Errorf("%w: %s", ErrBinaryAbsent, e.bin)
	}
	if detail == "" {
		detail = firstLine(stderr2)
	}
	if detail == "" {
		detail = fmt.Sprintf("version probe exited rc=%d", firstNonZero(rc, rc2))
	}
	return fmt.Errorf("%w: %s", ErrDaemonUnreachable, detail)
}

// Report produces the 7-tier classification for the daemon state
// correlated against workspaceRoots (the live workspace roots the
// analyse worker scanned).
//
// Error semantics: degradation (absent binary, unreachable daemon,
// partial collection failures) never errors — it lands in
// Warnings/Available so one missing capability cannot sink an analyse
// run. A non-nil error means the caller's context was cancelled.
func (e *Engine) Report(ctx context.Context, workspaceRoots []string) (DockerReport, error) {
	var rep DockerReport
	if ctx == nil {
		ctx = context.Background()
	}
	if e.bin == "" {
		rep.Warnings = append(rep.Warnings,
			"docker: binary not found on PATH; docker analysis unavailable")
		return rep, nil
	}
	if perr := e.Probe(ctx); perr != nil {
		if errors.Is(perr, ErrBinaryAbsent) || errors.Is(perr, ErrDaemonUnreachable) {
			rep.Warnings = append(rep.Warnings, "docker: analysis unavailable: "+perr.Error())
			return rep, nil
		}
		return rep, perr
	}
	if err := ctx.Err(); err != nil {
		return rep, err
	}
	rep.Available = true

	s := e.collect(ctx)
	ix := buildWorkspaceIndex(workspaceRoots, time.Now())
	tiers, classWarnings := classify(s, ix, time.Now())
	rep.Warnings = append(rep.Warnings, s.warnings...)
	rep.Warnings = append(rep.Warnings, classWarnings...)

	// Tier 5 (Windows host VHDX slack) is platform-gated; splice it in
	// front of tier 6 so the report stays ordered 0..6.
	t5, hostSlack, slackCmd, vhdxWarnings := e.hostSlackTier(s.dfTotal, s.dfOK)
	rep.Warnings = append(rep.Warnings, vhdxWarnings...)
	rep.HostSlack = hostSlack
	rep.SlackCommand = slackCmd
	if t5 != nil {
		at := len(tiers)
		for i, t := range tiers {
			if t.Tier == 6 {
				at = i
				break
			}
		}
		tiers = append(tiers[:at], append([]DockerTier{*t5}, tiers[at:]...)...)
	}
	rep.Tiers = tiers
	return rep, nil
}

// ---- hardened runner -------------------------------------------------

// run executes one allowlisted docker observation. err is non-nil only
// for infrastructure failures (spawn, timeout, cancellation); the CLI's
// own non-zero exits are reported through rc.
func (e *Engine) run(ctx context.Context, timeout time.Duration, args ...string) (stdout, stderr string, rc int, err error) {
	if err := allowlistCheck(args); err != nil {
		return "", "", -1, fmt.Errorf("%w: %q", err, args)
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, e.bin, args...)
	cmd.Env = childEnv(os.Environ())
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 10 * time.Second
	if serr := cmd.Start(); serr != nil {
		return "", "", -1, fmt.Errorf("%w: %s: %v", errSpawnStart, e.bin, serr)
	}
	werr := cmd.Wait()
	if cctx.Err() != nil && ctx.Err() == nil {
		return outBuf.String(), errBuf.String(), -1,
			fmt.Errorf("dockeradapter: docker %q timed out after %s: %w", args[:min(2, len(args))], timeout, cctx.Err())
	}
	if cctx.Err() != nil {
		return outBuf.String(), errBuf.String(), -1, ctx.Err()
	}
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			return outBuf.String(), errBuf.String(), ee.ExitCode(), nil
		}
		return outBuf.String(), errBuf.String(), -1, fmt.Errorf("dockeradapter: wait docker: %w", werr)
	}
	return outBuf.String(), errBuf.String(), 0, nil
}

// childEnv builds the docker child environment from scratch: a minimal
// OS substrate, the user-identity variables the CLI needs for its
// config/context discovery, and every inherited DOCKER_* variable
// (host/context/cert configuration must survive — unlike GIT_* these
// are the sanctioned routing controls). Everything else is dropped.
func childEnv(inherited []string) []string {
	names := []string{"PATH", "HOME", "USERPROFILE"}
	if runtime.GOOS == "windows" {
		names = append(names, "SYSTEMROOT", "COMSPEC", "WINDIR", "TMP", "TEMP", "PATHEXT")
	} else {
		names = append(names, "TMPDIR", "USER", "LANG", "LC_ALL", "TZ")
	}
	out := make([]string, 0, len(names)+8)
	for _, want := range names {
		for _, kv := range inherited {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			if envKeyMatches(kv[:eq], want) {
				out = append(out, kv)
				break
			}
		}
	}
	for _, kv := range inherited {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		if envKeyHasPrefix(kv[:eq], "DOCKER_") {
			out = append(out, kv)
		}
	}
	return out
}

// envKeyMatches compares an inherited variable name. Windows
// environment lookup is case-insensitive, so matching must be too.
func envKeyMatches(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// envKeyHasPrefix is the prefix form for passthrough families
// (DOCKER_*). Case-insensitive on Windows like the exact form.
func envKeyHasPrefix(name, prefix string) bool {
	if len(name) < len(prefix) {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name[:len(prefix)], prefix)
	}
	return name[:len(prefix)] == prefix
}

// spawnFailed reports whether err is a binary-resolution/exec failure.
func spawnFailed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errSpawnStart) {
		return true
	}
	var execErr *exec.Error
	return errors.As(err, &execErr)
}

// parentDone reports whether the PARENT context (not the per-call bound)
// ended, so cancellation is distinguished from a per-call timeout.
func parentDone(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() != nil
}

func firstNonZero(a, b int) int {
	if a != 0 {
		return a
	}
	return b
}

// ---- collection ------------------------------------------------------

// imageRec is one `docker image ls -a --format json` line.
type imageRec struct {
	ID           string  `json:"ID"`
	Repository   string  `json:"Repository"`
	Tag          string  `json:"Tag"`
	CreatedAt    string  `json:"CreatedAt"`
	CreatedSince string  `json:"CreatedSince"`
	Size         flexInt `json:"Size"`
	Containers   flexInt `json:"Containers"`
}

// containerRec is one `docker ps -a --format json` line.
type containerRec struct {
	ID      string     `json:"ID"`
	Names   string     `json:"Names"`
	Image   string     `json:"Image"`
	State   string     `json:"State"`
	Status  string     `json:"Status"`
	Labels  flexLabels `json:"Labels"`
	Created string     `json:"CreatedAt"`
}

// volumeLsRec is one `docker volume ls --format json` line.
type volumeLsRec struct {
	Name   string     `json:"Name"`
	Driver string     `json:"Driver"`
	Labels flexLabels `json:"Labels"`
	Links  flexInt    `json:"Links"`
}

// volumeInspectRec is one `docker volume inspect` object.
type volumeInspectRec struct {
	Name   string     `json:"Name"`
	Driver string     `json:"Driver"`
	Labels flexLabels `json:"Labels"`
}

// volume merges `volume ls` (links) with `volume inspect` (labels).
type volume struct {
	Name   string
	Labels map[string]string
	Links  int64
}

// buildxRec is one BuildKit cache record from `docker buildx du`.
type buildxRec struct {
	ID         string
	LastUsed   time.Time
	Created    time.Time
	Size       int64
	RecordType string
}

// dfRow is one `docker system df --format json` line.
type dfRow struct {
	Type string  `json:"Type"`
	Size flexInt `json:"Size"`
}

// snapshot is the full daemon observation classification works on.
type snapshot struct {
	images     []imageRec
	volumes    []volume
	containers []containerRec
	buildx     []buildxRec
	buildxOK   bool
	dfRows     []dfRow
	dfOK       bool
	dfTotal    int64
	warnings   []string
}

// collect gathers all daemon state. Every failure degrades to a warning;
// the only hard exit is caller cancellation (checked between commands).
func (e *Engine) collect(ctx context.Context) *snapshot {
	s := &snapshot{}

	if out, ok := e.jsonCommand(ctx, commandTimeout, "image", "ls", "-a"); ok {
		var skipped int
		s.images, skipped = parseImageLines(out)
		s.noteParse("image ls", skipped)
		if len(s.images) > maxParsedRecords {
			s.warnings = append(s.warnings, capWarning("image ls"))
			s.images = s.images[:maxParsedRecords]
		}
	}

	if out, ok := e.jsonCommand(ctx, commandTimeout, "ps", "-a"); ok {
		var skipped int
		s.containers, skipped = parseContainerLines(out)
		s.noteParse("ps", skipped)
		if len(s.containers) > maxParsedRecords {
			s.warnings = append(s.warnings, capWarning("ps"))
			s.containers = s.containers[:maxParsedRecords]
		}
	}

	e.collectVolumes(ctx, s)

	if out, rc, ok := e.runString(ctx, buildxTimeout, "buildx", "du", "--verbose", "--json"); ok && rc == 0 {
		s.buildx, s.buildxOK = parseBuildxDU(out)
		if !s.buildxOK {
			s.warnings = append(s.warnings,
				"docker: buildx cache usage not parsed (unrecognized output shape); tier 1 left empty")
		}
	} else if out2, rc2, ok2 := e.runString(ctx, buildxTimeout, "buildx", "du", "--verbose"); ok2 && rc2 == 0 {
		s.buildx, s.buildxOK = parseBuildxDU(out2)
		if !s.buildxOK {
			s.warnings = append(s.warnings,
				"docker: buildx cache usage not parsed (unrecognized output shape); tier 1 left empty")
		}
	} else {
		detail := "unavailable"
		if ok && rc != 0 {
			detail = fmt.Sprintf("exited rc=%d", rc)
		} else if ok2 && rc2 != 0 {
			detail = fmt.Sprintf("exited rc=%d", rc2)
		}
		s.warnings = append(s.warnings,
			"docker: buildx cache usage "+detail+"; tier 1 left empty (non-fatal)")
	}

	if out, ok := e.jsonCommand(ctx, commandTimeout, "system", "df"); ok {
		var skipped int
		s.dfRows, skipped = parseDFLines(out)
		s.noteParse("system df", skipped)
		s.dfOK = true
		for _, r := range s.dfRows {
			s.dfTotal += int64(r.Size)
		}
	} else {
		s.warnings = append(s.warnings,
			"docker: system df unavailable; logical totals unknown (host slack not derivable)")
	}
	return s
}

// jsonCommand runs one observation command in NDJSON mode, falling back
// to the template spelling for CLIs without the bare-json printer. ok
// reports a successful (rc==0) capture; degradation is the caller's job.
func (e *Engine) jsonCommand(ctx context.Context, timeout time.Duration, base ...string) (string, bool) {
	argv := append(append([]string{}, base...), NDJSON, ndjsonValue)
	out, _, rc, err := e.run(ctx, timeout, argv...)
	if parentDone(ctx, err) {
		return "", false
	}
	if err == nil && rc == 0 {
		return out, true
	}
	if spawnFailed(err) {
		return "", false
	}
	argvT := append(append([]string{}, base...), NDJSON, jsonTemplateValue)
	out2, _, rc2, err2 := e.run(ctx, timeout, argvT...)
	if parentDone(ctx, err2) {
		return "", false
	}
	return out2, err2 == nil && rc2 == 0
}

// runString is run() with the infrastructure-error collapsed into ok
// (spawn failure or hard error → ok=false; the caller degrades).
func (e *Engine) runString(ctx context.Context, timeout time.Duration, args ...string) (stdout string, rc int, ok bool) {
	out, _, code, err := e.run(ctx, timeout, args...)
	if parentDone(ctx, err) {
		return "", -1, false
	}
	if err != nil {
		return "", -1, false
	}
	return out, code, true
}

// collectVolumes lists volumes and enriches them through batched
// `docker volume inspect` calls (labels are authoritative there).
func (e *Engine) collectVolumes(ctx context.Context, s *snapshot) {
	out, ok := e.jsonCommand(ctx, commandTimeout, "volume", "ls")
	if !ok {
		s.warnings = append(s.warnings, "docker: volume ls unavailable; volume tiers left empty")
		return
	}
	ls, skipped := parseVolumeLsLines(out)
	s.noteParse("volume ls", skipped)
	if len(ls) > maxParsedRecords {
		s.warnings = append(s.warnings, capWarning("volume ls"))
		ls = ls[:maxParsedRecords]
	}
	names := make([]string, 0, len(ls))
	for _, r := range ls {
		s.volumes = append(s.volumes, volume{Name: r.Name, Labels: r.Labels, Links: int64(r.Links)})
		names = append(names, r.Name)
	}
	for start := 0; start < len(names); start += volumeInspectChunk {
		end := min(start+volumeInspectChunk, len(names))
		args := append([]string{"volume", "inspect"}, names[start:end]...)
		out, _, rc, err := e.run(ctx, commandTimeout, args...)
		if parentDone(ctx, err) {
			return
		}
		if err != nil || rc != 0 {
			s.warnings = append(s.warnings,
				fmt.Sprintf("docker: volume inspect batch failed (rc=%d); labels for those volumes come from ls only", rc))
			continue
		}
		var recs []volumeInspectRec
		if jerr := json.Unmarshal([]byte(out), &recs); jerr != nil {
			s.warnings = append(s.warnings, "docker: volume inspect output not parsed; labels for that batch come from ls only")
			continue
		}
		byName := make(map[string]map[string]string, len(recs))
		for _, r := range recs {
			byName[r.Name] = r.Labels
		}
		for i := range s.volumes {
			if labels, found := byName[s.volumes[i].Name]; found && len(labels) > 0 {
				s.volumes[i].Labels = labels
			}
		}
	}
}

// noteParse records malformed-line counts as warnings (skip, never fail).
func (s *snapshot) noteParse(cmd string, skipped int) {
	if skipped > 0 {
		s.warnings = append(s.warnings,
			fmt.Sprintf("docker: %s: %d malformed line(s) skipped", cmd, skipped))
	}
}

// capWarning is the truncation note for collection outputs bounded at
// maxParsedRecords.
func capWarning(cmd string) string {
	return fmt.Sprintf("docker: %s exceeded %d records; only the first %d kept",
		cmd, maxParsedRecords, maxParsedRecords)
}

func parseImageLines(out string) ([]imageRec, int) {
	var recs []imageRec
	skipped := decodeLines(out, func(line []byte) error {
		var r imageRec
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		recs = append(recs, r)
		return nil
	})
	return recs, skipped
}

func parseContainerLines(out string) ([]containerRec, int) {
	var recs []containerRec
	skipped := decodeLines(out, func(line []byte) error {
		var r containerRec
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		recs = append(recs, r)
		return nil
	})
	return recs, skipped
}

func parseVolumeLsLines(out string) ([]volumeLsRec, int) {
	var recs []volumeLsRec
	skipped := decodeLines(out, func(line []byte) error {
		var r volumeLsRec
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		recs = append(recs, r)
		return nil
	})
	return recs, skipped
}

func parseDFLines(out string) ([]dfRow, int) {
	var recs []dfRow
	skipped := decodeLines(out, func(line []byte) error {
		var r dfRow
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		recs = append(recs, r)
		return nil
	})
	return recs, skipped
}

// decodeLines feeds every non-empty output line to decode; unparsable
// lines are counted and skipped, never fatal, never a panic.
func decodeLines(out string, decode func([]byte) error) int {
	skipped := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := decode([]byte(line)); err != nil {
			skipped++
		}
	}
	return skipped
}

// parseBuildxDU accepts both observed buildx du shapes: one JSON object
// carrying a Records/records array, or NDJSON record lines. ok is false
// when nothing parseable was found (shape drift → honest degradation).
func parseBuildxDU(out string) ([]buildxRec, bool) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, false
	}
	parseRecord := func(raw json.RawMessage) (buildxRec, bool) {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return buildxRec{}, false
		}
		var rec buildxRec
		if v, ok := fields["ID"]; ok {
			_ = json.Unmarshal(v, &rec.ID)
		}
		if rec.ID == "" {
			return buildxRec{}, false
		}
		if v, ok := fields["RecordType"]; ok {
			_ = json.Unmarshal(v, &rec.RecordType)
		}
		if v, ok := fields["Usage"]; ok {
			var u struct {
				Size flexInt `json:"Size"`
			}
			if json.Unmarshal(v, &u) == nil {
				rec.Size = int64(u.Size)
			}
		}
		parse := func(key string) (time.Time, bool) {
			v, ok := fields[key]
			if !ok {
				return time.Time{}, false
			}
			var s *string
			if err := json.Unmarshal(v, &s); err != nil || s == nil || *s == "" {
				return time.Time{}, false
			}
			return parseDockerTime(*s)
		}
		rec.LastUsed, _ = parse("LastUsedAt")
		rec.Created, _ = parse("CreatedAt")
		return rec, true
	}

	// Whole-output object form.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
		for _, key := range []string{"Records", "records"} {
			if rawList, ok := obj[key]; ok {
				var list []json.RawMessage
				if json.Unmarshal(rawList, &list) == nil {
					var recs []buildxRec
					for _, raw := range list {
						if rec, ok := parseRecord(raw); ok {
							recs = append(recs, rec)
						}
					}
					return recs, true
				}
			}
		}
	}
	// NDJSON fallback.
	var recs []buildxRec
	found := false
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if rec, ok := parseRecord(json.RawMessage(line)); ok {
			recs = append(recs, rec)
			found = true
		}
	}
	return recs, found
}

// parseDockerTime accepts the timestamp spellings docker emits
// (RFC3339[Nano] for inspect/buildx records; Go time.String() forms for
// ls CreatedAt). ok=false when no layout matches (age stays unknown and
// the item is never classified stale — honesty over coverage).
func parseDockerTime(s string) (time.Time, bool) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseSince parses docker's human "CreatedSince" spellings
// ("2 months ago"). No JSON equivalent exists for these strings.
func parseSince(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, " ago") {
		return 0, false
	}
	s = strings.TrimSuffix(s, " ago")
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, false
	}
	unit := strings.ToLower(parts[1])
	switch {
	case strings.HasPrefix(unit, "second"):
		return time.Duration(n) * time.Second, true
	case strings.HasPrefix(unit, "minute"):
		return time.Duration(n) * time.Minute, true
	case strings.HasPrefix(unit, "hour"):
		return time.Duration(n) * time.Hour, true
	case strings.HasPrefix(unit, "day"):
		return time.Duration(n) * 24 * time.Hour, true
	case strings.HasPrefix(unit, "week"):
		return time.Duration(n) * 7 * 24 * time.Hour, true
	case strings.HasPrefix(unit, "month"):
		return time.Duration(n) * 30 * 24 * time.Hour, true
	case strings.HasPrefix(unit, "year"):
		return time.Duration(n) * 365 * 24 * time.Hour, true
	}
	return 0, false
}

// imageCreatedAt resolves an image row's creation time, preferring the
// absolute CreatedAt and falling back to the relative CreatedSince.
func imageCreatedAt(r imageRec, now time.Time) (time.Time, bool) {
	if r.CreatedAt != "" {
		if t, ok := parseDockerTime(r.CreatedAt); ok {
			return t, true
		}
	}
	if r.CreatedSince != "" {
		if d, ok := parseSince(r.CreatedSince); ok {
			return now.Add(-d), true
		}
	}
	return time.Time{}, false
}

// ---- tolerant JSON field types ---------------------------------------

// flexInt accepts a JSON number or a humanized byte string
// ("412MB", "1.2GiB", "8192").
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" {
		*f = 0
		return nil
	}
	if strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		n, err := parseByteSize(str)
		if err != nil {
			return err
		}
		*f = flexInt(n)
		return nil
	}
	var num float64
	if err := json.Unmarshal(b, &num); err != nil {
		return err
	}
	*f = flexInt(int64(num))
	return nil
}

// parseByteSize understands docker's humanized sizes (power-of-1000
// kB/MB/GB and IEC KiB/MiB/GiB).
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	numPart, unit := s[:i], strings.TrimSpace(strings.ToLower(s[i:]))
	var base float64
	if err := json.Unmarshal([]byte(numPart), &base); err != nil {
		return 0, fmt.Errorf("bad size %q", s)
	}
	mult := 1.0
	switch unit {
	case "", "b":
		mult = 1
	case "kb", "k":
		mult = 1000
	case "mb", "m":
		mult = 1000 * 1000
	case "gb", "g":
		mult = 1000 * 1000 * 1000
	case "tb", "t":
		mult = 1000 * 1000 * 1000 * 1000
	case "kib":
		mult = 1 << 10
	case "mib":
		mult = 1 << 20
	case "gib":
		mult = 1 << 30
	case "tib":
		mult = 1 << 40
	default:
		return 0, fmt.Errorf("unknown unit in %q", s)
	}
	return int64(base * mult), nil
}

// flexLabels accepts docker's two label spellings: a JSON object (modern
// --format json) or the legacy "k=v,k=v" string.
type flexLabels map[string]string

func (f *flexLabels) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		return nil
	}
	if strings.HasPrefix(s, "{") {
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		*f = m
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	m := map[string]string{}
	for _, pair := range strings.Split(str, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, found := strings.Cut(pair, "=")
		if !found {
			continue // tolerate stray fragments
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	*f = m
	return nil
}

// ---- small helpers ----------------------------------------------------

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func daysAgo(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days <= 0 {
		return "today"
	}
	if days == 1 {
		return "1 day ago"
	}
	return fmt.Sprintf("%d days ago", days)
}

// joinIDs renders at most maxCommandIDs ids joined by spaces; overflow
// is marked so the copyable command never silently under-covers.
func joinIDs(ids []string) string {
	if len(ids) > maxCommandIDs {
		kept := ids[:maxCommandIDs]
		return strings.Join(kept, " ") + fmt.Sprintf("  # +%d more: rerun ebb analyse after this batch", len(ids)-maxCommandIDs)
	}
	return strings.Join(ids, " ")
}

// displayPath shortens a path for Detail strings.
func displayPath(p string) string {
	if len(p) > 80 {
		return "..." + p[len(p)-77:]
	}
	return p
}
