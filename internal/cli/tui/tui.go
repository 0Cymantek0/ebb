// Package tui provides the dependency-free terminal menu primitives
// behind Ebb's bare interactive invocations (ADR D032): a framed
// single-selection picker (Select) for `ebb open` and a toggleable
// checklist (Checklist) for `ebb reclaim`.
//
// Rationale: Foundation §3.2 selects a native Go CLI and prefers the
// standard library over frameworks, so these menus are built on nothing
// beyond golang.org/x/term (raw mode) and, on Windows, x/sys/windows
// console-mode calls. There is no screen buffer, no event pump, and no
// goroutine anywhere in the package.
//
// Operating discipline:
//
//   - Raw mode is enabled only while a menu is on screen; the restore
//     function returned by Terminal.MakeRaw runs exactly once on every
//     exit path (confirm, Esc, Ctrl+C, context cancellation, I/O
//     failure) via defer.
//   - Rendering is a full-frame repaint: every frame rewrites all of
//     its lines (CUU up-move + per-line EL erase), so a resize or a
//     lost sequence can never leave partial garbage behind. On exit the
//     frame is cleared, SGR is reset, the cursor is shown again, and
//     output ends at column 0 of a fresh line carrying the one-line
//     outcome (e.g. "selected: renderer").
//   - Cancellation: Esc and Ctrl+C (0x03 in raw mode) return
//     ErrCanceled; context cancellation is checked between runes and
//     returns ErrCanceled wrapping the context cause. Honest
//     limitation: a ReadRune already blocked on a silent terminal is
//     not interruptible without goroutines, so cancellation takes
//     effect at the next keypress (in practice Ctrl+C itself is that
//     keypress, since raw mode delivers it as a rune).
//   - Fallback: when the output console cannot process VT escape
//     sequences (legacy conhost) or raw mode is unavailable, both
//     menus degrade to a plain numbered-list prompt ("enter a number")
//     that contains no escape codes at all, so legacy or piped
//     sessions never see garbage.
//
// Terminals are injected (Terminal / StdioTerminal) so tests drive the
// menus with scripted runes against a bytes.Buffer; rendering is
// deterministic for a given model, size, and state.
package tui

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// Terminal is the testability seam every menu consumes. Production
// code passes StdioTerminal(os.Stdin, os.Stderr); tests pass a fake
// with scripted runes, a capture buffer, and an injected size.
type Terminal interface {
	// Size reports the usable terminal dimensions in cells.
	Size() (cols, rows int, err error)
	// MakeRaw puts the input into raw mode and returns the restore
	// function. It returns a no-op restore (and a nil error) when the
	// input is not a real console, and an error when the input is a
	// console raw mode cannot be applied to.
	MakeRaw() (restore func(), err error)
	// ReadRune reads the next input rune (raw mode: no echo, no line
	// buffering, arrows arrive as ESC sequences, Ctrl+C as 0x03). It
	// carries the io.RuneReader signature (vet's stdmethods check
	// requires it, and it lets implementations embed bufio.Reader);
	// menus ignore the byte count.
	ReadRune() (rune, int, error)
	// Write sends bytes to the output stream.
	Write(p []byte) (int, error)
}

// VTCapable is an optional Terminal capability: terminals that can
// report whether their output honors ANSI/VT escape sequences.
// StdioTerminal implements it (probing the Windows console; POSIX
// terminals report true). A Terminal that does not implement it is
// assumed capable and only degrades to the numbered fallback when raw
// mode fails. Implementations may probe by transiently flipping the
// console mode; probing must not leak mode changes.
type VTCapable interface {
	Terminal
	VTSupported() bool
}

// bufferedTerminal reports pending buffered input, letting the input
// decoder distinguish a lone Esc keypress from the start of an ESC [
// sequence without blocking (arrow keys arrive as one chunk, so bytes
// are already buffered when the ESC rune is consumed).
type bufferedTerminal interface {
	Buffered() int
}

var (
	// ErrCanceled reports user cancellation (Esc, Ctrl+C, or context
	// cancellation). Context cancellation is wrapped inside:
	// errors.Is(err, ErrCanceled) && errors.Is(err, context.Canceled).
	ErrCanceled = errors.New("tui: canceled")
	// ErrUnsupportedTerminal reports that the terminal cannot deliver
	// an interactive session: the capability probes left only the
	// numbered fallback and its input source failed (for example EOF
	// on an exhausted pipe). Callers should fall back to non-interactive
	// mode (ADR D032).
	ErrUnsupportedTerminal = errors.New("tui: terminal does not support interactive input")
)

const (
	// minWidth is the smallest usable menu width; narrower terminals
	// are rendered at this width and expected to scroll horizontally
	// rather than wrap the frame into garbage.
	minWidth = 40
	// defaultCols / defaultRows are used when the terminal size cannot
	// be determined (Size error or non-console streams).
	defaultCols = 80
	defaultRows = 24

	ctrlC = 0x03
	esc   = 0x1B
)

// StdioTerminal returns a Terminal over the given streams. Production
// wraps os.Stdin/os.Stderr; tests wrap a bytes.Reader and a
// bytes.Buffer (Size then reports the fixed default). It is safe for
// sequential reuse by successive menus within one process.
func StdioTerminal(r io.Reader, w io.Writer) Terminal {
	return &stdioTerminal{Reader: bufio.NewReader(r), r: r, w: w}
}

// stdioTerminal implements Terminal, VTCapable and bufferedTerminal;
// ReadRune and Buffered are promoted from the embedded bufio.Reader.
type stdioTerminal struct {
	*bufio.Reader
	r io.Reader
	w io.Writer
}

// Size returns the console size, preferring the output handle (on
// Windows GetConsoleScreenBufferInfo needs a screen-buffer handle, so
// probing only stdin's fd would always fail) and falling back to the
// input handle, then to the fixed default. An unknown size must
// degrade the layout, never the session, so it never errors.
func (s *stdioTerminal) Size() (int, int, error) {
	for _, f := range []*os.File{asFile(s.w), asFile(s.r)} {
		if f == nil {
			continue
		}
		if cols, rows, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 && rows > 0 {
			return cols, rows, nil
		}
	}
	return defaultCols, defaultRows, nil
}

// asFile extracts an *os.File without importing a reflect-based hack.
func asFile(w any) *os.File {
	if f, ok := w.(*os.File); ok {
		return f
	}
	return nil
}

// MakeRaw enables raw mode on a console input (composing the Windows
// output-console VT restore on top of term.Restore) and returns the
// composed restore, guarded to run at most once. Non-console inputs
// get a no-op restore and no error.
func (s *stdioTerminal) MakeRaw() (func(), error) {
	var restores []func() // enabled in order, restored in reverse (LIFO)
	if f, ok := s.r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fd := int(f.Fd())
		state, err := term.MakeRaw(fd)
		if err != nil {
			return func() {}, err
		}
		restores = append(restores, func() { term.Restore(fd, state) })
	}
	if r := vtSetup(); r != nil {
		restores = append(restores, r)
	}
	if len(restores) == 0 {
		return func() {}, nil
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := len(restores) - 1; i >= 0; i-- {
				restores[i]()
			}
		})
	}, nil
}

// Write sends bytes to the output stream.
func (s *stdioTerminal) Write(p []byte) (int, error) { return s.w.Write(p) }

// VTSupported probes whether the output honors VT sequences (on
// Windows: the console accepts ENABLE_VIRTUAL_TERMINAL_PROCESSING; on
// other platforms terminals are ANSI-native and the piped/dumb cases
// are the caller's gate).
func (s *stdioTerminal) VTSupported() bool { return vtProbe() }

// terminalSize resolves the usable size, falling back to the default
// on error or nonsense values.
func terminalSize(t Terminal) (cols, rows int) {
	cols, rows, err := t.Size()
	if err != nil || cols <= 0 || rows <= 0 {
		return defaultCols, defaultRows
	}
	return cols, rows
}

// interactiveCapable reports whether the framed rendering should be
// attempted for t.
func interactiveCapable(t Terminal) bool {
	if vt, ok := t.(VTCapable); ok {
		return vt.VTSupported()
	}
	return true
}

func cancelErr(cause error) error {
	return fmt.Errorf("%w: %w", ErrCanceled, cause)
}

func wrapReadErr(err error) error {
	return fmt.Errorf("%w: input failed: %w", ErrUnsupportedTerminal, err)
}

func wrapWriteErr(err error) error {
	return fmt.Errorf("tui: write failed: %w", err)
}

// ---- input decoding ----

type keyKind int

const (
	keyNone keyKind = iota
	keyUp
	keyDown
	keyEnter
	keyCancel
	keySpace
	keyToggleAll
)

// readRune reads one rune, honoring ctx between runes (the documented
// cancellation limitation: an already-blocked read finishes first).
func readRune(ctx context.Context, t Terminal) (rune, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r, _, err := t.ReadRune()
	return r, err
}

// nextKey decodes the next key press. Minimal ANSI input: ESC [ A/B
// (up/down; ESC [ C/D and other finals are tolerated harmlessly),
// j/k as vim aliases, Enter as CR or LF, Ctrl+C as 0x03. A lone ESC
// (nothing buffered behind it) cancels; on terminals that cannot
// report buffered input, ESC is treated as cancel only when the next
// rune is not '['.
func nextKey(ctx context.Context, t Terminal) (keyKind, error) {
	r, err := readRune(ctx, t)
	if err != nil {
		return keyNone, err
	}
	switch r {
	case ctrlC:
		return keyCancel, nil
	case esc:
		if b, ok := t.(bufferedTerminal); ok && b.Buffered() == 0 {
			return keyCancel, nil // lone Esc press
		}
		r2, err := readRune(ctx, t)
		if err != nil {
			return keyNone, err
		}
		if r2 != '[' {
			return keyCancel, nil // stray ESC + byte: treat as Esc
		}
		r3, err := readRune(ctx, t)
		if err != nil {
			return keyNone, err
		}
		switch r3 {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		default:
			return keyNone, nil // C/D/H/F/modifier bytes tolerated
		}
	case '\r', '\n':
		return keyEnter, nil
	case 'k':
		return keyUp, nil
	case 'j':
		return keyDown, nil
	case ' ':
		return keySpace, nil
	case 'a':
		return keyToggleAll, nil
	}
	return keyNone, nil
}

// ---- display-width helpers (compact wcwidth approximation) ----

// runeWidth approximates the terminal cell count of r: 0 for combining
// marks and zero-width joins, 2 for the common East Asian / fullwidth /
// emoji blocks, 1 otherwise. Good enough for layout; documented
// approximation, not a full wcwidth table.
func runeWidth(r rune) int {
	switch {
	case r == 0,
		r < 0x20 || (r >= 0x7F && r < 0xA0),
		r >= 0x0300 && r <= 0x036F, // combining diacritics
		r >= 0x200B && r <= 0x200F, // zero-width space/join
		r >= 0xFE00 && r <= 0xFE0F: // variation selectors
		return 0
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E, // CJK radicals, Kangxi
		r >= 0x3041 && r <= 0x33FF, // kana .. CJK compatibility
		r >= 0x3400 && r <= 0x4DBF, // CJK extension A
		r >= 0x4E00 && r <= 0x9FFF, // CJK unified
		r >= 0xA000 && r <= 0xA4CF, // Yi, Hangul syllables start
		r >= 0xAC00 && r <= 0xD7A3, // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF, // CJK compatibility ideographs
		r >= 0xFE10 && r <= 0xFE19, // vertical forms
		r >= 0xFE30 && r <= 0xFE6F, // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60, // fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F, // emoji
		r >= 0x1F900 && r <= 0x1F9FF,
		r >= 0x20000 && r <= 0x3FFFD: // CJK extension B+
		return 2
	}
	return 1
}

// displayWidth sums the cell widths of s.
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

// fit truncates s to at most w cells, appending an ellipsis when
// truncation happens.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if displayWidth(s) <= w {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runeWidth(r)
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	b.WriteRune('…')
	return b.String()
}

// fitPad truncates then right-pads s to exactly w cells.
func fitPad(s string, w int) string {
	s = fit(s, w)
	return s + strings.Repeat(" ", max(0, w-displayWidth(s)))
}

// ---- frame rendering ----

// Row is one selectable line of a menu.
type Row struct {
	// Label is the primary left-aligned text.
	Label string
	// Detail is secondary text laid out after the label column.
	Detail string
	// Right is right-aligned end-of-line text (sizes, states).
	Right string
	// Disabled rows are rendered dimmed, skipped by navigation, and
	// can be neither selected nor toggled.
	Disabled bool
}

// frameSpec is the render input for one full frame.
type frameSpec struct {
	title, subtitle string
	footer          []string
	rows            []Row    // all rows (for stable column widths)
	visibleRows     []Row    // the windowed slice actually drawn
	prefix          []string // per visible row: "" or "[X] "/"[ ] "
	cursorVisible   int      // index into visibleRows; -1 when none
	scrollUp        bool     // rows hidden above the window
	scrollDown      bool     // rows hidden below the window
}

// renderFrame produces the frame's lines: bordered box (title embedded
// in the top rule, scroll arrows replacing rule dashes), subtitle
// block, visible rows with the ▸ cursor, and footer hint lines below
// the box. Every line is exactly width cells (or minWidth when
// narrower), so a repaint always overwrites the previous frame.
func renderFrame(v frameSpec, cols int) []string {
	width := max(cols, minWidth)
	inner := width - 4
	lines := make([]string, 0, len(v.visibleRows)+len(v.footer)+6)
	var topInd, botInd rune
	if v.scrollUp {
		topInd = '▲'
	}
	if v.scrollDown {
		botInd = '▼'
	}
	lines = append(lines, borderLine(v.title, "┌", "┐", topInd, width))
	if v.subtitle != "" {
		lines = append(lines, innerLine(v.subtitle, inner))
		lines = append(lines, innerLine("", inner))
	}
	labelMax, rightMax := 0, 0
	for _, r := range v.rows {
		labelMax = max(labelMax, displayWidth(r.Label))
		rightMax = max(rightMax, displayWidth(r.Right))
	}
	for k, row := range v.visibleRows {
		marker := "  "
		if k == v.cursorVisible {
			marker = "▸ "
		}
		cells := max(0, inner-2-displayWidth(v.prefix[k]))
		core := marker + v.prefix[k] + layRow(cells, row, labelMax, rightMax)
		if row.Disabled {
			core = "\x1b[2m" + core + "\x1b[0m"
		}
		lines = append(lines, "│ "+core+" │")
	}
	lines = append(lines, borderLine("", "└", "┘", botInd, width))
	for _, f := range v.footer {
		lines = append(lines, fit(f, width))
	}
	return lines
}

// layRow lays label/detail/right into exactly cells display cells.
// Columns are sized from the model-wide maxima so they stay stable
// while the window scrolls; detail is the flexible filler truncated
// with an ellipsis.
func layRow(cells int, row Row, labelMax, rightMax int) string {
	budget := cells
	rightW := 0
	if rightMax > 0 {
		rightW = min(rightMax, cells/3)
		budget -= rightW + 2 // gap before the right column
	}
	labelW := min(labelMax+2, budget) // padded label + 2-space gap
	core := fitPad(row.Label, max(0, labelW))
	if d := budget - labelW; d > 0 && row.Detail != "" {
		core += fit(row.Detail, d)
	}
	if rightW > 0 && row.Right != "" {
		r := fitPad(row.Right, rightW)
		if pad := cells - displayWidth(core) - displayWidth(r); pad > 0 {
			core += strings.Repeat(" ", pad)
		}
		core += r
	}
	return fitPad(core, cells)
}

// borderLine builds "┌─ Title ────┐" / "└────┘" with the scroll arrow
// (▲ above the window, ▼ below it) replacing one rule dash next to the
// corner when indicator is non-zero.
func borderLine(title, left, right string, indicator rune, width int) string {
	prefix := left
	if title != "" {
		prefix = left + "─ " + fit(title, max(1, width-8)) + " "
	}
	tail := "─" + right
	if indicator != 0 {
		tail = string(indicator) + "─" + right
	}
	fill := max(0, width-displayWidth(prefix)-displayWidth(tail))
	return prefix + strings.Repeat("─", fill) + tail
}

// innerLine pads content into the box interior: "│ text │".
func innerLine(content string, inner int) string {
	return "│ " + fitPad(content, inner) + " │"
}

// ---- painter: full-repaint discipline over a Terminal ----

// painter repaints a fixed-shape frame region in place and collapses
// it on exit. Frame bytes: CUU up-move over the previous frame, then
// per line CR + EL-erase + content + CRLF, so every frame is a full
// repaint and the cursor always rests at column 0 of the line below
// the frame.
type painter struct {
	t    Terminal
	last int // lines painted by the last frame
}

func (p *painter) hide() error {
	if _, err := p.t.Write([]byte("\x1b[?25l")); err != nil {
		return wrapWriteErr(err)
	}
	return nil
}

func (p *painter) frame(lines []string) error {
	var b bytes.Buffer
	if p.last > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", p.last)
	}
	for _, ln := range lines {
		b.WriteString("\r\x1b[2K")
		b.WriteString(ln)
		b.WriteString("\r\n")
	}
	p.last = len(lines)
	if _, err := p.t.Write(b.Bytes()); err != nil {
		return wrapWriteErr(err)
	}
	return nil
}

// clear collapses the painted region, leaving the cursor at column 0
// of the line where the frame top used to be.
func (p *painter) clear() error {
	if p.last == 0 {
		return nil
	}
	seq := fmt.Sprintf("\x1b[%dA\r\x1b[J", p.last)
	p.last = 0
	if _, err := p.t.Write([]byte(seq)); err != nil {
		return wrapWriteErr(err)
	}
	return nil
}

// finish writes the exit line: cursor visible, SGR reset, one-line
// outcome, newline. Satisfies the exit invariant (column 0 of a fresh
// line, no active escape sequences).
func (p *painter) finish(text string) error {
	if _, err := p.t.Write([]byte("\x1b[?25h\x1b[0m" + text + "\r\n")); err != nil {
		return wrapWriteErr(err)
	}
	return nil
}

// ---- shared interactive controller ----

// menu drives the interactive loop shared by Select and Checklist.
// Differences live in the prefix func (checkbox vs plain) and in the
// checked slice (nil in select mode disables space/toggle-all).
type menu struct {
	t               Terminal
	p               painter
	title, subtitle string
	footer          []string
	rows            []Row
	prefix          func(i int) string
	checked         []bool
	cursor, window  int
	cols, rowsTerm  int
}

// visibleCount derives the row window from the terminal height minus
// the frame chrome, always leaving one spare line below the frame.
func (m *menu) visibleCount() int {
	v := m.rowsTerm - 2 - len(m.footer) - 1
	if m.subtitle != "" {
		v -= 2
	}
	v = max(v, 1)
	return min(v, len(m.rows))
}

// clampWindow shifts the window so cursor stays visible.
func clampWindow(cursor, window, visible, n int) int {
	visible = min(max(visible, 1), n)
	if cursor < 0 {
		if window < 0 || window > n-visible {
			return 0
		}
		return window
	}
	switch {
	case cursor < window:
		return cursor
	case cursor >= window+visible:
		return cursor - visible + 1
	}
	return window
}

func (m *menu) paint() error {
	vis := m.visibleCount()
	m.window = clampWindow(m.cursor, m.window, vis, len(m.rows))
	spec := frameSpec{
		title:         m.title,
		subtitle:      m.subtitle,
		footer:        m.footer,
		rows:          m.rows,
		visibleRows:   m.rows[m.window : m.window+vis],
		cursorVisible: m.cursor - m.window,
		scrollUp:      m.window > 0,
		scrollDown:    m.window+vis < len(m.rows),
	}
	spec.prefix = make([]string, vis)
	for k := range spec.prefix {
		if m.prefix != nil {
			spec.prefix[k] = m.prefix(m.window + k)
		}
	}
	return m.p.frame(renderFrame(spec, m.cols))
}

// move steps the cursor by delta with wrap-around, skipping disabled
// rows; with no enabled row it stays put.
func (m *menu) move(delta int) {
	n := len(m.rows)
	if n == 0 {
		return
	}
	start := m.cursor
	for i := 0; i < n; i++ {
		m.cursor = ((m.cursor+delta)%n + n) % n
		if !m.rows[m.cursor].Disabled {
			return
		}
	}
	m.cursor = start
}

func toggleAllState(checked []bool, rows []Row) {
	all := true
	for i, r := range rows {
		if !r.Disabled && !checked[i] {
			all = false
			break
		}
	}
	v := !all
	for i, r := range rows {
		if !r.Disabled {
			checked[i] = v
		}
	}
}

// run paints the first frame and pumps keys until Enter/Cancel. It
// returns the final cursor index (or -1 with the error). Read failures
// wrap ErrUnsupportedTerminal; ctx cancellation wraps ErrCanceled
// around the context cause.
func (m *menu) run(ctx context.Context) (int, error) {
	if err := m.p.hide(); err != nil {
		return -1, err
	}
	if err := m.paint(); err != nil {
		return -1, err
	}
	for {
		if ce := ctx.Err(); ce != nil {
			return -1, cancelErr(ce)
		}
		k, err := nextKey(ctx, m.t)
		if err != nil {
			if ce := ctx.Err(); ce != nil {
				return -1, cancelErr(ce)
			}
			return -1, wrapReadErr(err)
		}
		changed := false
		switch k {
		case keyUp:
			m.move(-1)
			changed = true
		case keyDown:
			m.move(1)
			changed = true
		case keyEnter:
			return m.cursor, nil
		case keyCancel:
			return -1, ErrCanceled
		case keySpace:
			if m.checked != nil && m.cursor >= 0 && !m.rows[m.cursor].Disabled {
				m.checked[m.cursor] = !m.checked[m.cursor]
				changed = true
			}
		case keyToggleAll:
			if m.checked != nil {
				toggleAllState(m.checked, m.rows)
				changed = true
			}
		}
		if changed {
			if err := m.paint(); err != nil {
				return -1, err
			}
		}
	}
}

// plainOut writes plain-mode lines, tracking whether the cursor ends
// at column 0 so the exit can always land on a fresh line without
// emitting a single escape code.
type plainOut struct {
	t     Terminal
	fresh bool
}

func newPlainOut(t Terminal) *plainOut { return &plainOut{t: t, fresh: true} }

func (p *plainOut) line(s string) error {
	if _, err := p.t.Write([]byte(s + "\n")); err != nil {
		return wrapWriteErr(err)
	}
	p.fresh = true
	return nil
}

func (p *plainOut) prompt(s string) error {
	if _, err := p.t.Write([]byte(s)); err != nil {
		return wrapWriteErr(err)
	}
	p.fresh = false
	return nil
}

// endPrompt terminates a pending prompt line so subsequent output
// (reprinted lists, feedback) starts at column 0.
func (p *plainOut) endPrompt() error {
	if p.fresh {
		return nil
	}
	if _, err := p.t.Write([]byte("\n")); err != nil {
		return wrapWriteErr(err)
	}
	p.fresh = true
	return nil
}

// close terminates any pending prompt line and writes the final
// outcome line ("" writes only the terminating newline if needed).
func (p *plainOut) close(text string) error {
	if err := p.endPrompt(); err != nil {
		return err
	}
	if text == "" {
		return nil
	}
	if _, err := p.t.Write([]byte(text + "\n")); err != nil {
		return wrapWriteErr(err)
	}
	return nil
}

// plainLines renders the numbered-list fallback: title, subtitle,
// numbered rows (with checkbox prefixes for checklists), all free of
// escape codes.
func plainLines(title, subtitle string, rows []Row, prefix []string, cols int) []string {
	width := max(cols, minWidth)
	var lines []string
	if title != "" {
		lines = append(lines, fit(title, width))
	}
	if subtitle != "" {
		lines = append(lines, fit(subtitle, width))
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	labelMax, rightMax := 0, 0
	for _, r := range rows {
		labelMax = max(labelMax, displayWidth(r.Label))
		rightMax = max(rightMax, displayWidth(r.Right))
	}
	for i, row := range rows {
		num := fmt.Sprintf("%d) ", i+1)
		pfx := ""
		if i < len(prefix) {
			pfx = prefix[i]
		}
		cells := max(0, width-2-displayWidth(num)-displayWidth(pfx))
		lines = append(lines, fit("  "+num+pfx+layRow(cells, row, labelMax, rightMax), width))
	}
	lines = append(lines, "")
	return lines
}

// readPlainLine reads one cooked input line keeping only runes accepted
// by keep (digits, and for checklists the all-toggle letter). Esc and
// Ctrl+C cancel; Enter (CR or LF) finishes the line. Cancel and read
// failures close the plain output before returning.
func readPlainLine(ctx context.Context, t Terminal, out *plainOut, keep func(rune) bool) (string, error) {
	var buf []byte
	for {
		if ce := ctx.Err(); ce != nil {
			out.close("canceled")
			return "", cancelErr(ce)
		}
		r, err := readRune(ctx, t)
		if err != nil {
			if ce := ctx.Err(); ce != nil {
				out.close("canceled")
				return "", cancelErr(ce)
			}
			out.close("")
			return "", wrapReadErr(err)
		}
		switch {
		case r == esc || r == ctrlC:
			out.close("canceled")
			return "", ErrCanceled
		case r == '\r' || r == '\n':
			if err := out.endPrompt(); err != nil {
				return "", err
			}
			return string(buf), nil
		default:
			if keep(r) && len(buf) < 9 {
				buf = append(buf, byte(r))
			}
		}
	}
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

func keepDigits(r rune) bool { return isDigit(r) }

func keepDigitsOrAll(r rune) bool { return isDigit(r) || r == 'a' || r == 'A' }

// firstEnabled returns the first non-disabled row index, or -1.
func firstEnabled(rows []Row) int {
	for i, r := range rows {
		if !r.Disabled {
			return i
		}
	}
	return -1
}
