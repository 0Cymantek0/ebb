package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var pickRows = []Row{
	{Label: "renderer", Detail: "Parked: 3 days ago", Right: "(Node/pnpm)"},
	{Label: "ml-pipeline", Detail: "Parked: 2 weeks ago", Right: "(Python/uv)"},
	{Label: "firmware-core", Detail: "Parked: 1 month ago", Right: "(Rust)"},
	{Label: "legacy-api", Detail: "Parked: 4 months ago", Right: "(Node/npm)"},
}

func TestSelectEnterReturnsFirstRow(t *testing.T) {
	f := newFake("\r")
	idx, err := Select(context.Background(), f, SelectModel{
		Title:    "Ebb: Select Parked Workspace to Restore",
		Subtitle: "Use ↑/↓ to navigate, Enter to open, Esc to exit",
		Rows:     pickRows,
		Footer:   []string{"[ Enter: Restore & Rebuild ]   [ Esc: exit ]"},
	})
	if err != nil || idx != 0 {
		t.Fatalf("Select = %d, %v; want 0, nil", idx, err)
	}
	out := f.Out.String()
	for _, want := range []string{
		"Ebb: Select Parked Workspace to Restore",
		"Use ↑/↓ to navigate",
		"▸ renderer",
		"ml-pipeline",
		"[ Enter: Restore & Rebuild ]",
		"selected: renderer",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("raw restore called %d times; want exactly 1", f.RestoreCalls)
	}
}

// TestSelectGoldenExactOutput pins the full byte stream of the simplest
// session: hide cursor, one frame, clear, exit line. Hand-computed
// golden (independent of the renderer's own helpers).
func TestSelectGoldenExactOutput(t *testing.T) {
	f := newFake("\r")
	f.Cols, f.Rows = 40, 24
	idx, err := Select(context.Background(), f, SelectModel{
		Title: "Pick",
		Rows:  []Row{{Label: "alpha"}, {Label: "beta"}},
	})
	if err != nil || idx != 0 {
		t.Fatalf("Select = %d, %v; want 0, nil", idx, err)
	}
	want := "\x1b[?25l" +
		"\r\x1b[2K┌─ Pick " + strings.Repeat("─", 30) + "─┐\r\n" +
		"\r\x1b[2K│ ▸ alpha" + strings.Repeat(" ", 29) + " │\r\n" +
		"\r\x1b[2K│   beta" + strings.Repeat(" ", 30) + " │\r\n" +
		"\r\x1b[2K└" + strings.Repeat("─", 37) + "─┘\r\n" +
		"\x1b[4A\r\x1b[J" +
		"\x1b[?25h\x1b[0mselected: alpha\r\n"
	if got := f.Out.String(); got != want {
		t.Fatalf("golden mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestSelectNavigationAndWrapAround(t *testing.T) {
	cases := []struct {
		script string
		want   int
	}{
		{"\r", 0},
		{"j\r", 1},
		{"jjj\r", 3},
		{"k\r", 3}, // wrap up from the first row to the last
		{"jjjjjjjj\r", 0},
		{"kk\r", 2},
		{"\x1b[B\x1b[B\r", 2}, // real arrow sequences
		{"\x1b[A\r", 3},       // arrow up wraps to the last row
	}
	for _, c := range cases {
		f := newFake(c.script)
		idx, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
		if err != nil {
			t.Errorf("script %q: %v", c.script, err)
			continue
		}
		if idx != c.want {
			t.Errorf("script %q: idx = %d; want %d", c.script, idx, c.want)
		}
		if f.RestoreCalls != 1 {
			t.Errorf("script %q: restore calls = %d; want 1", c.script, f.RestoreCalls)
		}
	}
}

func TestSelectDisabledRowsSkippedAndDimmed(t *testing.T) {
	rows := []Row{
		{Label: "alpha"},
		{Label: "beta", Disabled: true},
		{Label: "gamma"},
		{Label: "delta", Disabled: true},
	}
	// Down from 0 skips beta; up from 0 wraps to gamma, skipping delta.
	cases := []struct {
		script string
		want   int
	}{
		{"j\r", 2},
		{"k\r", 2},
		{"jj\r", 0}, // 0 -> 2 -> wraps to 0
		{"jjj\r", 2},
	}
	for _, c := range cases {
		f := newFake(c.script)
		idx, err := Select(context.Background(), f, SelectModel{Rows: rows})
		if err != nil || idx != c.want {
			t.Errorf("script %q: Select = %d, %v; want %d, nil", c.script, idx, err, c.want)
		}
	}
	// Disabled rows render dimmed and never carry the cursor.
	f := newFake("j\r")
	if _, err := Select(context.Background(), f, SelectModel{Rows: rows}); err != nil {
		t.Fatal(err)
	}
	out := f.Out.String()
	if !strings.Contains(out, "\x1b[2m  beta") {
		t.Error("disabled row not dimmed (marker + label must sit inside the dim span)")
	}
	frames := extractFrames(out)
	if c := strings.Count(frames[0], "\x1b[2m"); c != 2 {
		t.Errorf("first frame dims %d rows; want exactly the 2 disabled ones", c)
	}
	for _, frame := range frames {
		if strings.Contains(frame, "▸ beta") {
			t.Fatal("cursor rendered on a disabled row")
		}
	}
}

func TestSelectEnterUnreachableOnDisabled(t *testing.T) {
	// Every navigation cycle must land on an enabled row.
	f := newFake("kjkj\r")
	rows := []Row{{Label: "a"}, {Label: "b", Disabled: true}}
	idx, err := Select(context.Background(), f, SelectModel{Rows: rows})
	if err != nil || idx != 0 {
		t.Fatalf("Select = %d, %v; want 0, nil (only enabled row)", idx, err)
	}
}

func TestSelectCancelPaths(t *testing.T) {
	for name, script := range map[string]string{"esc": "\x1b", "ctrlc": "\x03"} {
		f := newFake(script)
		idx, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
		if !errors.Is(err, ErrCanceled) || idx != -1 {
			t.Fatalf("%s: Select = %d, %v; want -1, ErrCanceled", name, idx, err)
		}
		if out := f.Out.String(); !strings.Contains(out, "canceled") {
			t.Errorf("%s: missing canceled outcome line", name)
		}
		if f.RestoreCalls != 1 {
			t.Errorf("%s: restore calls = %d; want 1", name, f.RestoreCalls)
		}
	}
}

func TestSelectCtxCancellationUnblocksLoop(t *testing.T) {
	// Cancel mid-navigation via the read hook: the loop must observe it
	// between runes and return ErrCanceled wrapping the context cause.
	ctx, cancel := context.WithCancel(context.Background())
	f := newFake("jj\r")
	f.OnRead = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	idx, err := Select(ctx, f, SelectModel{Rows: pickRows})
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Select = %d, %v; want ErrCanceled wrapping context.Canceled", idx, err)
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1 on the ctx-cancel path", f.RestoreCalls)
	}
}

func TestSelectPreCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFake("") // no runes: cancellation must not need input
	if _, err := Select(ctx, f, SelectModel{Rows: pickRows}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Select err = %v; want context.Canceled", err)
	}
	if f.Reads() != 0 {
		t.Fatalf("reads = %d; want 0 (ctx checked before the first read)", f.Reads())
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1", f.RestoreCalls)
	}
}

func TestSelectExhaustedInputIsUnsupported(t *testing.T) {
	f := newFake("") // blocked input that dies: EOF
	_, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
	if !errors.Is(err, ErrUnsupportedTerminal) {
		t.Fatalf("Select err = %v; want ErrUnsupportedTerminal", err)
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1 on the read-failure path", f.RestoreCalls)
	}
}

func TestSelectWindowingFiveRowsThreeLineViewport(t *testing.T) {
	rows := []Row{
		{Label: "row-zero"},
		{Label: "row-one"},
		{Label: "row-two"},
		{Label: "row-three"},
		{Label: "row-four"},
	}
	f := newFake("jjj\r")
	f.Cols, f.Rows = 60, 6 // 6 - 2 borders - 1 spare = 3 visible
	idx, err := Select(context.Background(), f, SelectModel{Rows: rows})
	if err != nil || idx != 3 {
		t.Fatalf("Select = %d, %v; want 3, nil", idx, err)
	}
	frames := extractFrames(f.Out.String())
	if len(frames) != 4 { // initial + three repaints
		t.Fatalf("frames = %d; want 4", len(frames))
	}
	last := frameText(frames[len(frames)-1])
	for _, want := range []string{"row-one", "row-two", "row-three", "▲"} {
		if !strings.Contains(last, want) {
			t.Errorf("final window missing %q:\n%s", want, last)
		}
	}
	if !strings.Contains(last, "▼") {
		t.Error("final window missing ▼ (row-four hidden below)")
	}
	for _, hidden := range []string{"row-zero", "row-four"} {
		if strings.Contains(last, hidden) {
			t.Errorf("window leaked hidden row %q", hidden)
		}
	}
	// First frame: top of the list, only ▼ shown.
	first := frameText(frames[0])
	if strings.Contains(first, "▲") || !strings.Contains(first, "▼") || !strings.Contains(first, "row-zero") {
		t.Errorf("first window indicators wrong:\n%s", first)
	}
}

func TestSelectWindowingWrapUp(t *testing.T) {
	rows := []Row{
		{Label: "row-zero"}, {Label: "row-one"}, {Label: "row-two"},
		{Label: "row-three"}, {Label: "row-four"},
	}
	f := newFake("k\r")
	f.Cols, f.Rows = 60, 6
	idx, err := Select(context.Background(), f, SelectModel{Rows: rows})
	if err != nil || idx != 4 {
		t.Fatalf("Select = %d, %v; want 4, nil (wrap up)", idx, err)
	}
	frames := extractFrames(f.Out.String())
	last := frameText(frames[len(frames)-1])
	if !strings.Contains(last, "▲") || strings.Contains(last, "▼") {
		t.Errorf("wrapped-up window indicators wrong:\n%s", last)
	}
	if !strings.Contains(last, "row-four") || strings.Contains(last, "row-zero") {
		t.Errorf("wrapped-up window content wrong:\n%s", last)
	}
}

func TestSelectEveryFrameIsFullRepaint(t *testing.T) {
	f := newFake("jjk\x1b[Bk\r")
	f.Cols, f.Rows = 60, 6 // force windowing while navigating
	if _, err := Select(context.Background(), f, SelectModel{
		Rows: []Row{
			{Label: "row-zero"}, {Label: "row-one"}, {Label: "row-two"},
			{Label: "row-three"}, {Label: "row-four"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	frames := extractFrames(f.Out.String())
	if len(frames) < 5 {
		t.Fatalf("frames = %d; want at least 5", len(frames))
	}
	wantLines := strings.Count(frames[0], "\r\n")
	for i, frame := range frames {
		if got := strings.Count(frame, "\r\n"); got != wantLines {
			t.Errorf("frame %d has %d lines; want %d (stable frame height)", i, got, wantLines)
		}
		if erases, lines := strings.Count(frame, "\r\x1b[2K"), strings.Count(frame, "\r\n"); erases != lines {
			t.Errorf("frame %d: %d erases for %d lines; every line must be erased+rewritten", i, erases, lines)
		}
	}
}

func TestSelectNarrowTerminalTruncates(t *testing.T) {
	f := newFake("\r")
	f.Cols, f.Rows = 20, 24 // clamped to minWidth
	long := strings.Repeat("very-long-workspace-name-", 4)
	if _, err := Select(context.Background(), f, SelectModel{
		Title: "Pick",
		Rows:  []Row{{Label: long}},
	}); err != nil {
		t.Fatal(err)
	}
	out := f.Out.String()
	if !strings.Contains(out, "…") {
		t.Fatal("narrow render missing truncation ellipsis")
	}
	for _, frame := range extractFrames(out) {
		for _, ln := range strings.Split(frameText(frame), "\n") {
			if ln == "" {
				continue
			}
			if w := displayWidth(stripSGR(ln)); w > minWidth {
				t.Fatalf("line wider than minWidth: %q (w=%d)", ln, w)
			}
		}
	}
}

func TestSelectRightColumnAtLineEnd(t *testing.T) {
	f := newFake("\r")
	if _, err := Select(context.Background(), f, SelectModel{Rows: pickRows}); err != nil {
		t.Fatal(err)
	}
	first := frameText(extractFrames(f.Out.String())[0])
	if !strings.Contains(first, "(Node/pnpm) │") {
		t.Errorf("right column not flush against the border:\n%s", first)
	}
}

func TestSelectPlainFallback(t *testing.T) {
	f := newFake("2\r")
	f.VT = false // legacy conhost: no VT sequences
	idx, err := Select(context.Background(), f, SelectModel{
		Title: "Ebb: Select", Subtitle: "Pick one", Rows: pickRows,
	})
	if err != nil || idx != 1 {
		t.Fatalf("Select = %d, %v; want 1, nil", idx, err)
	}
	out := f.Out.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("plain fallback emitted escape codes: %q", out)
	}
	for _, want := range []string{"Ebb: Select", "1) renderer", "2) ml-pipeline", "Enter a number (1-4)", "selected: ml-pipeline"} {
		if !strings.Contains(out, want) {
			t.Errorf("plain output missing %q", want)
		}
	}
	if !strings.HasSuffix(out, "selected: ml-pipeline\n") {
		t.Errorf("plain output must end on a fresh outcome line: %q", out)
	}
	if f.MakeRawCalls != 0 || f.RestoreCalls != 0 {
		t.Fatalf("plain path touched raw mode (make=%d restore=%d); want 0/0", f.MakeRawCalls, f.RestoreCalls)
	}
}

func TestSelectPlainInvalidThenValid(t *testing.T) {
	f := newFake("9\r2\r")
	f.VT = false
	idx, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
	if err != nil || idx != 1 {
		t.Fatalf("Select = %d, %v; want 1, nil", idx, err)
	}
	if out := f.Out.String(); !strings.Contains(out, "invalid choice: 9") {
		t.Errorf("missing invalid-choice feedback: %q", out)
	}
}

func TestSelectPlainEscAndEmptyEnterCancel(t *testing.T) {
	for name, script := range map[string]string{"esc": "\x1b", "empty-enter": "\r"} {
		f := newFake(script)
		f.VT = false
		idx, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
		if !errors.Is(err, ErrCanceled) || idx != -1 {
			t.Fatalf("%s: Select = %d, %v; want -1, ErrCanceled", name, idx, err)
		}
		if out := f.Out.String(); !strings.HasSuffix(out, "canceled\n") {
			t.Errorf("%s: plain cancel must still end on a fresh line: %q", name, out)
		}
	}
}

func TestSelectRawFailureDegradesToPlain(t *testing.T) {
	f := newFake("1\r")
	f.VT = true
	f.RawErr = errors.New("console raw mode refused") // e.g. cooked-only handle
	idx, err := Select(context.Background(), f, SelectModel{Rows: pickRows})
	if err != nil || idx != 0 {
		t.Fatalf("Select = %d, %v; want 0, nil via numbered fallback", idx, err)
	}
	if f.MakeRawCalls != 1 || f.RestoreCalls != 0 {
		t.Fatalf("raw probe accounting wrong (make=%d restore=%d); want 1/0", f.MakeRawCalls, f.RestoreCalls)
	}
	if out := f.Out.String(); strings.Contains(out, "\x1b") {
		t.Fatalf("fallback after raw failure emitted escapes: %q", out)
	}
}

func TestSelectExitHygiene(t *testing.T) {
	// VT mode: ends with CRLF after the outcome, SGR reset and cursor
	// visible, and nothing painted after the exit line.
	f := newFake("\r")
	if _, err := Select(context.Background(), f, SelectModel{Rows: pickRows}); err != nil {
		t.Fatal(err)
	}
	out := f.Out.String()
	if !strings.HasSuffix(out, "\r\n") {
		t.Fatal("VT output must end with CRLF (column 0 of a fresh line)")
	}
	if !strings.Contains(out, "\x1b[?25h") || !strings.Contains(out, "\x1b[0m") {
		t.Fatal("exit must show the cursor and reset SGR")
	}
	exitAt := strings.Index(out, "\x1b[?25h")
	if strings.Contains(out[exitAt:], "\x1b[2K") {
		t.Fatal("frame content painted after the exit sequence")
	}
}

func TestSelectEmptyAndAllDisabled(t *testing.T) {
	if _, err := Select(context.Background(), newFake("\r"), SelectModel{}); err == nil {
		t.Fatal("empty model must error")
	}
	if _, err := Select(context.Background(), newFake("\r"), SelectModel{
		Rows: []Row{{Label: "x", Disabled: true}},
	}); err == nil {
		t.Fatal("all-disabled model must error")
	}
}
