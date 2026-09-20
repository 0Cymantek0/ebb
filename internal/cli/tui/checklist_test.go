package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var reclaimRows = []Row{
	{Label: "node_modules", Detail: "(pnpm dependencies)", Right: "14.2 GiB"},
	{Label: ".next/cache", Detail: "(Next.js build cache)", Right: "3.8 GiB"},
	{Label: "test-recordings", Detail: "(local video captures)", Right: "2.1 GiB"},
}

func TestChecklistInitialStateRendered(t *testing.T) {
	f := newFake("\r")
	state, err := Checklist(context.Background(), f, ChecklistModel{
		Title:    `Ebb: Reclaim Space in "renderer"`,
		Subtitle: "Select groups to clean",
		Rows:     reclaimRows,
		Initial:  []bool{true, true, false},
		Footer:   []string{"[ Space: Toggle ]   [ Enter: Reclaim Selected ]   [ Esc: Cancel ]"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 3 || !state[0] || !state[1] || state[2] {
		t.Fatalf("state = %v; want the initial state returned unchanged on Enter", state)
	}
	first := frameText(extractFrames(f.Out.String())[0])
	for _, want := range []string{"▸ [X] node_modules", "[X] .next/cache", "[ ] test-recordings", "[ Space: Toggle ]"} {
		if !strings.Contains(first, want) {
			t.Errorf("first frame missing %q:\n%s", want, first)
		}
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1", f.RestoreCalls)
	}
}

func TestChecklistSpaceTogglesCurrentRow(t *testing.T) {
	f := newFake(" \r") // space toggles row 0, enter confirms
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if err != nil {
		t.Fatal(err)
	}
	if !state[0] || state[1] || state[2] {
		t.Fatalf("state = %v; want [true false false]", state)
	}
	frames := extractFrames(f.Out.String())
	if len(frames) != 2 {
		t.Fatalf("frames = %d; want 2 (initial + one repaint)", len(frames))
	}
	if second := frameText(frames[1]); !strings.Contains(second, "▸ [X] node_modules") {
		t.Errorf("repaint missing checked cursor row:\n%s", second)
	}
	if out := f.Out.String(); !strings.Contains(out, "confirmed: 1 of 3 selected") {
		t.Errorf("missing summary outcome: %q", out)
	}
}

func TestChecklistToggleAllSemantics(t *testing.T) {
	// 'a' checks every enabled row; 'a' again unchecks them all.
	f := newFake("aa\r")
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range state {
		if c {
			t.Fatalf("state = %v; want all false after double toggle-all", state)
		}
	}
	f2 := newFake("a\r")
	state2, err := Checklist(context.Background(), f2, ChecklistModel{Rows: reclaimRows})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range state2 {
		if !c {
			t.Fatalf("state2 = %v; want all true after toggle-all (row %d)", state2, i)
		}
	}
}

func TestChecklistDisabledRowsNeverToggle(t *testing.T) {
	rows := []Row{
		{Label: "enabled-a"},
		{Label: "enabled-b"},
		{Label: "locked", Disabled: true},
	}
	// Cursor starts on the first enabled row; navigation can never rest
	// on "locked"; toggle-all and initial state leave it unchecked.
	f := newFake("a\r")
	state, err := Checklist(context.Background(), f, ChecklistModel{
		Rows:    rows,
		Initial: []bool{false, false, true}, // disabled entry must be ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if state[2] {
		t.Fatal("disabled row is checked; it must stay untoggleable")
	}
	if !state[0] || !state[1] {
		t.Fatalf("state = %v; want enabled rows checked by toggle-all", state)
	}
	// Walking the whole list with space can only toggle enabled rows.
	f2 := newFake(" j j k \r")
	state2, err := Checklist(context.Background(), f2, ChecklistModel{Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if state2[2] {
		t.Fatal("space toggled a disabled row")
	}
}

func TestChecklistNavigationSkipsDisabled(t *testing.T) {
	rows := []Row{
		{Label: "a", Disabled: true},
		{Label: "b"},
	}
	f := newFake(" \r") // cursor must start on b (first enabled)
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if state[0] || !state[1] {
		t.Fatalf("state = %v; want the first enabled row toggled, not the disabled one", state)
	}
}

func TestChecklistCancelReturnsZeroValue(t *testing.T) {
	f := newFake("\x1b")
	state, err := Checklist(context.Background(), f, ChecklistModel{
		Rows:    reclaimRows,
		Initial: []bool{true, true, true},
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v; want ErrCanceled", err)
	}
	if state != nil {
		t.Fatalf("state = %v; want nil on cancel", state)
	}
	if out := f.Out.String(); !strings.Contains(out, "canceled") {
		t.Error("missing canceled outcome")
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1 on cancel", f.RestoreCalls)
	}
}

func TestChecklistCtrlCCancels(t *testing.T) {
	f := newFake("\x03")
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if !errors.Is(err, ErrCanceled) || state != nil {
		t.Fatalf("Checklist = %v, %v; want nil, ErrCanceled", state, err)
	}
}

func TestChecklistCtxCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := newFake("j")
	f.OnRead = func(n int) {
		if n == 1 {
			cancel()
		}
	}
	state, err := Checklist(ctx, f, ChecklistModel{Rows: reclaimRows})
	if !errors.Is(err, ErrCanceled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want ErrCanceled wrapping context.Canceled", err)
	}
	if state != nil || f.RestoreCalls != 1 {
		t.Fatalf("state = %v restore = %d; want nil / 1", state, f.RestoreCalls)
	}
}

func TestChecklistInitialLengthMismatch(t *testing.T) {
	f := newFake("\r")
	if _, err := Checklist(context.Background(), f, ChecklistModel{
		Rows:    reclaimRows,
		Initial: []bool{true},
	}); err == nil {
		t.Fatal("Initial length mismatch must error")
	}
	if f.MakeRawCalls != 0 {
		t.Fatal("validation must happen before any terminal mutation")
	}
}

func TestChecklistExitHygiene(t *testing.T) {
	f := newFake(" \r")
	if _, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows}); err != nil {
		t.Fatal(err)
	}
	out := f.Out.String()
	if !strings.HasSuffix(out, "\r\n") || !strings.Contains(out, "\x1b[?25h") || !strings.Contains(out, "\x1b[0m") {
		t.Fatalf("checklist exit violates hygiene: %q", out[len(out)-80:])
	}
}

func TestChecklistPlainFallback(t *testing.T) {
	f := newFake("1\r\r") // toggle row 1, then confirm
	f.VT = false
	state, err := Checklist(context.Background(), f, ChecklistModel{
		Title: "Ebb: Reclaim", Subtitle: "Select groups", Rows: reclaimRows,
		Initial: []bool{false, false, false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !state[0] || state[1] || state[2] {
		t.Fatalf("state = %v; want [true false false]", state)
	}
	out := f.Out.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("plain checklist emitted escapes: %q", out)
	}
	// The list is reprinted after the toggle so the checkbox stays visible.
	if !strings.Contains(out, "1) [X] node_modules") {
		t.Errorf("reprinted list missing checked row: %q", out)
	}
	if !strings.HasSuffix(out, "confirmed: 1 of 3 selected\n") {
		t.Errorf("plain outcome wrong: %q", out[len(out)-60:])
	}
	if f.MakeRawCalls != 0 {
		t.Fatal("plain path must not touch raw mode")
	}
}

func TestChecklistPlainToggleAllAndConfirm(t *testing.T) {
	f := newFake("a\r\r")
	f.VT = false
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range state {
		if !c {
			t.Fatalf("state = %v; want all true (row %d)", state, i)
		}
	}
}

func TestChecklistPlainDisabledRefused(t *testing.T) {
	rows := []Row{{Label: "a"}, {Label: "locked", Disabled: true}}
	f := newFake("2\r\r")
	f.VT = false
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if state[1] {
		t.Fatal("plain mode toggled a disabled row")
	}
	if out := f.Out.String(); !strings.Contains(out, "row 2 cannot be toggled") {
		t.Errorf("missing refusal feedback: %q", out)
	}
}

func TestChecklistPlainCancel(t *testing.T) {
	f := newFake("\x1b")
	f.VT = false
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if !errors.Is(err, ErrCanceled) || state != nil {
		t.Fatalf("Checklist = %v, %v; want nil, ErrCanceled", state, err)
	}
	if out := f.Out.String(); !strings.HasSuffix(out, "canceled\n") {
		t.Errorf("plain cancel must end on a fresh line: %q", out)
	}
}

func TestChecklistErrorPathExitHygiene(t *testing.T) {
	f := newFake("") // input dies: read-failure (non-cancel) path
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: reclaimRows})
	if !errors.Is(err, ErrUnsupportedTerminal) || state != nil {
		t.Fatalf("Checklist = %v, %v; want nil, ErrUnsupportedTerminal", state, err)
	}
	out := f.Out.String()
	if !strings.HasSuffix(out, "\r\n") || !strings.Contains(out, "\x1b[?25h") || !strings.Contains(out, "\x1b[0m") {
		t.Fatalf("error-path exit violates hygiene (frame cleared, cursor shown, fresh line): %q", out[max(0, len(out)-60):])
	}
	if f.RestoreCalls != 1 {
		t.Fatalf("restore calls = %d; want 1 on the read-failure path", f.RestoreCalls)
	}
}

func TestChecklistAllDisabledConfirmsUnchecked(t *testing.T) {
	rows := []Row{{Label: "locked", Disabled: true}}
	f := newFake("\r")
	state, err := Checklist(context.Background(), f, ChecklistModel{Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	if len(state) != 1 || state[0] {
		t.Fatalf("state = %v; want [false] (Enter confirms with nothing toggleable)", state)
	}
}
