package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// FakeTerminal is the scriptable Terminal used by every menu test:
// scripted runes, a capture buffer, an injectable size, a VT flag, and
// counters asserting the raw-mode restore discipline.
type FakeTerminal struct {
	Script       []rune
	Out          bytes.Buffer
	Cols, Rows   int
	SizeErr      error
	RawErr       error
	VT           bool
	MakeRawCalls int
	RestoreCalls int
	OnRead       func(call int) // fires before each scripted rune is served

	pos       int
	readCalls int
}

func newFake(script string) *FakeTerminal {
	return &FakeTerminal{Script: []rune(script), Cols: 80, Rows: 24, VT: true}
}

func (f *FakeTerminal) Size() (int, int, error) { return f.Cols, f.Rows, f.SizeErr }

func (f *FakeTerminal) MakeRaw() (func(), error) {
	f.MakeRawCalls++
	if f.RawErr != nil {
		return func() {}, f.RawErr
	}
	return func() { f.RestoreCalls++ }, nil
}

func (f *FakeTerminal) ReadRune() (rune, int, error) {
	f.readCalls++
	if f.OnRead != nil {
		f.OnRead(f.readCalls)
	}
	if f.pos >= len(f.Script) {
		return 0, 0, io.EOF
	}
	r := f.Script[f.pos]
	f.pos++
	return r, 1, nil
}

func (f *FakeTerminal) Write(p []byte) (int, error) { return f.Out.Write(p) }

// VTSupported implements VTCapable; the flag forces either rendering
// mode deterministically regardless of the host console.
func (f *FakeTerminal) VTSupported() bool { return f.VT }

// Buffered reports pending scripted runes so ESC-sequence decoding can
// distinguish a lone Esc from ESC [ A without blocking.
func (f *FakeTerminal) Buffered() int { return len(f.Script) - f.pos }

func (f *FakeTerminal) Reads() int { return f.readCalls }

// unbufferedTerminal strips the optional capabilities (Buffered,
// VTSupported) to exercise the decoding fallbacks.
type unbufferedTerminal struct{ inner *FakeTerminal }

func (u unbufferedTerminal) Size() (int, int, error)      { return u.inner.Size() }
func (u unbufferedTerminal) MakeRaw() (func(), error)     { return u.inner.MakeRaw() }
func (u unbufferedTerminal) ReadRune() (rune, int, error) { return u.inner.ReadRune() }
func (u unbufferedTerminal) Write(p []byte) (int, error)  { return u.inner.Write(p) }

// upMove matches the CUU sequences that precede every repaint and the
// final clear, so frames can be split apart.
var upMove = regexp.MustCompile(`\x1b\[\d+A`)

// extractFrames splits VT output into painted frames (dropping the
// exit clear and the hide/show cursor chatter) so repaint invariants
// can be asserted frame by frame.
func extractFrames(out string) []string {
	if i := strings.Index(out, "\x1b[?25h"); i >= 0 {
		out = out[:i]
	}
	var frames []string
	for _, part := range upMove.Split(out, -1) {
		if strings.Contains(part, "\x1b[J") || !strings.Contains(part, "\r\x1b[2K") {
			continue
		}
		frames = append(frames, part)
	}
	return frames
}

func frameText(frame string) string {
	frame = strings.ReplaceAll(frame, "\x1b[?25l", "") // cursor-hide chatter
	var b strings.Builder
	for _, ln := range strings.Split(frame, "\r\n") {
		b.WriteString(strings.TrimPrefix(ln, "\r\x1b[2K"))
		b.WriteByte('\n')
	}
	return b.String()
}

// ---- StdioTerminal ----

func TestStdioTerminalReadWriteAndBuffered(t *testing.T) {
	var out bytes.Buffer
	st := StdioTerminal(strings.NewReader("ab"), &out)
	r1, _, err := st.ReadRune()
	if err != nil || r1 != 'a' {
		t.Fatalf("ReadRune = %q, %v; want 'a', nil", r1, err)
	}
	if n := st.(interface{ Buffered() int }).Buffered(); n != 1 {
		t.Fatalf("Buffered after one rune = %d; want 1", n)
	}
	if _, _, err := st.ReadRune(); err != nil || st.(interface{ Buffered() int }).Buffered() != 0 {
		t.Fatalf("second ReadRune failed: %v", err)
	}
	if _, err := st.Write([]byte("x")); err != nil || out.String() != "x" {
		t.Fatalf("Write passthrough broken: %q, %v", out.String(), err)
	}
}

func TestStdioTerminalSizeDefaultsForNonFile(t *testing.T) {
	st := StdioTerminal(strings.NewReader(""), &bytes.Buffer{})
	cols, rows, err := st.Size()
	if err != nil || cols != defaultCols || rows != defaultRows {
		t.Fatalf("Size = %d, %d, %v; want %d, %d, nil", cols, rows, err, defaultCols, defaultRows)
	}
}

func TestStdioTerminalMakeRawNoOpForNonConsole(t *testing.T) {
	st := StdioTerminal(strings.NewReader(""), &bytes.Buffer{})
	restore, err := st.MakeRaw()
	if err != nil {
		t.Fatalf("MakeRaw on a non-console returned %v; want nil error with no-op restore", err)
	}
	restore()
	restore() // guarded: a second call must stay safe
}

func TestStdioTerminalVTSupportedNoPanic(t *testing.T) {
	st := StdioTerminal(strings.NewReader(""), &bytes.Buffer{})
	vt := st.(VTCapable).VTSupported() // must not panic on any platform
	if runtime.GOOS != "windows" && !vt {
		t.Fatalf("VTSupported on %s = false; want true (POSIX terminals are ANSI-native)", runtime.GOOS)
	}
}

// ---- width helpers ----

func TestRuneWidth(t *testing.T) {
	cases := []struct {
		r    rune
		want int
	}{
		{'a', 1}, {'─', 1}, {'…', 1}, {'▸', 1}, {'[', 1},
		{'中', 2}, {'あ', 2}, {'한', 2}, {'Ａ', 2},
		{0x0301, 0}, {0x200B, 0}, {0xFE0F, 0},
		{0x1F600, 2},
	}
	for _, c := range cases {
		if got := runeWidth(c.r); got != c.want {
			t.Errorf("runeWidth(%U) = %d; want %d", c.r, got, c.want)
		}
	}
}

func TestFitTruncatesWithEllipsis(t *testing.T) {
	cases := []struct {
		s, want string
		w       int
	}{
		{"abcdefgh", "abcd…", 5},
		{"abc", "abc", 5},
		{"", "", 3},
		{"中中中", "中…", 4},
		{"abc", "", 0},
	}
	for _, c := range cases {
		if got := fit(c.s, c.w); got != c.want {
			t.Errorf("fit(%q, %d) = %q; want %q", c.s, c.w, got, c.want)
		}
	}
}

func TestFitPadExactWidth(t *testing.T) {
	for _, s := range []string{"a", "中文", "abcdefghij"} {
		got := fitPad(s, 6)
		if w := displayWidth(got); w != 6 {
			t.Errorf("fitPad(%q, 6) = %q with width %d; want 6", s, got, w)
		}
	}
	if got := fitPad("ab", 5); got != "ab   " {
		t.Errorf("fitPad padding = %q; want %q", got, "ab   ")
	}
}

// ---- key decoding ----

func TestNextKeyDecoding(t *testing.T) {
	cases := []struct {
		script string
		want   keyKind
	}{
		{"\x1b[A", keyUp},
		{"\x1b[B", keyDown},
		{"\x1b[C", keyNone}, // tolerated harmlessly
		{"\x1b[D", keyNone},
		{"\x1b[H", keyNone},
		{"\x1b", keyCancel}, // lone Esc: nothing buffered behind it
		{"j", keyDown},
		{"k", keyUp},
		{"\r", keyEnter},
		{"\n", keyEnter},
		{" ", keySpace},
		{"a", keyToggleAll},
		{"\x03", keyCancel},
		{"x", keyNone},
	}
	for _, c := range cases {
		f := newFake(c.script)
		got, err := nextKey(context.Background(), f)
		if err != nil {
			t.Errorf("nextKey(%q) error: %v", c.script, err)
			continue
		}
		if got != c.want {
			t.Errorf("nextKey(%q) = %v; want %v", c.script, got, c.want)
		}
	}
}

func TestNextKeyUnbufferedTerminal(t *testing.T) {
	// Without Buffered(), ESC [ A still decodes as a sequence.
	u := unbufferedTerminal{newFake("\x1b[A")}
	if k, err := nextKey(context.Background(), u); err != nil || k != keyUp {
		t.Fatalf("nextKey on unbuffered terminal = %v, %v; want keyUp", k, err)
	}
	// A lone ESC with nothing behind it surfaces the next read's error
	// (real terminals block here; the limitation is documented).
	u2 := unbufferedTerminal{newFake("\x1b")}
	if _, err := nextKey(context.Background(), u2); err == nil {
		t.Fatal("nextKey after lone ESC on unbuffered terminal: want the follow-up read error")
	}
}

// ---- rendering primitives ----

func TestBorderLine(t *testing.T) {
	got := borderLine("Pick", "┌", "┐", 0, 40)
	want := "┌─ Pick " + strings.Repeat("─", 30) + "─┐"
	if got != want {
		t.Fatalf("borderLine = %q; want %q", got, want)
	}
	got = borderLine("Pick", "┌", "┐", '▲', 40)
	want = "┌─ Pick " + strings.Repeat("─", 29) + "▲─┐"
	if got != want {
		t.Fatalf("borderLine(▲) = %q; want %q", got, want)
	}
	got = borderLine("", "└", "┘", '▼', 40)
	want = "└" + strings.Repeat("─", 36) + "▼─┘"
	if got != want {
		t.Fatalf("borderLine(▼) = %q; want %q", got, want)
	}
}

func TestRenderFrameBoxWidthsExact(t *testing.T) {
	rows := []Row{
		{Label: "渲染器", Detail: "Parked: 3 days ago", Right: "18.4 GiB"},
		{Label: "ml-pipeline", Detail: "非常に長い詳細情報です", Right: "(Python/uv)"},
		{Label: "disabled-one", Detail: "d", Right: "r", Disabled: true},
	}
	for _, width := range []int{20, 40, 52, 80} {
		spec := frameSpec{
			title: "Ebb: Select", subtitle: "Use arrows to navigate",
			rows: rows, visibleRows: rows, cursorVisible: 1,
			scrollUp: true, scrollDown: true,
			prefix: []string{"", "", ""},
			footer: []string{"[ Enter: open ]   [ Esc: exit ]"},
		}
		for _, ln := range renderFrame(spec, width) {
			if !strings.HasPrefix(ln, "│") && !strings.HasPrefix(ln, "┌") && !strings.HasPrefix(ln, "└") {
				continue // footer lines may be shorter than the frame
			}
			if w := displayWidth(stripSGR(ln)); w != max(width, minWidth) {
				t.Errorf("width %d: box line %q has width %d; want %d", width, ln, w, max(width, minWidth))
			}
		}
	}
}

// stripSGR removes SGR sequences so widths can be measured on lines
// that carry dim markers (an independent oracle: counted explicitly,
// not via the renderer).
func stripSGR(s string) string {
	out := strings.ReplaceAll(s, "\x1b[2m", "")
	return strings.ReplaceAll(out, "\x1b[0m", "")
}

func TestPlainLinesContainNoEscapes(t *testing.T) {
	lines := plainLines("Title", "Sub", []Row{{Label: "a"}, {Label: "b"}}, []string{"[X] ", "[ ] "}, 80)
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "\x1b") {
		t.Fatalf("plain fallback contains escape codes: %q", joined)
	}
	for _, want := range []string{"Title", "Sub", "1) [X] a", "2) [ ] b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plain list missing %q in %q", want, joined)
		}
	}
}

// ---- platform shims ----

func TestVtSetupCallable(t *testing.T) {
	if r := vtSetup(); r != nil {
		r()
		r() // restoring twice must stay harmless
	}
}

// ---- cross-cutting invariants ----

func TestNoGoroutinesSpawned(t *testing.T) {
	before := runtime.NumGoroutine()
	f := newFake("jj k \x1b[B\r")
	if _, err := Select(context.Background(), f, SelectModel{Rows: []Row{{Label: "a"}, {Label: "b"}, {Label: "c"}}}); err != nil {
		t.Fatalf("Select: %v", err)
	}
	f2 := newFake(" a\r")
	if _, err := Checklist(context.Background(), f2, ChecklistModel{Rows: []Row{{Label: "a"}, {Label: "b"}}}); err != nil {
		t.Fatalf("Checklist: %v", err)
	}
	if after := runtime.NumGoroutine(); before != after {
		t.Fatalf("goroutines before=%d after=%d; the package must spawn none", before, after)
	}
}

func TestErrCanceledWrapsContextCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cancelErr(ctx.Err())
	if !errors.Is(err, ErrCanceled) {
		t.Fatal("ErrCanceled not matched")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("context.Canceled not matched")
	}
}
