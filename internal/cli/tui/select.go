package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// SelectModel describes one single-selection menu (the `ebb open`
// workspace picker).
type SelectModel struct {
	Title    string
	Subtitle string
	Rows     []Row
	// Footer holds key hints rendered below the frame (one line each).
	Footer []string
}

// Select shows a framed single-selection menu on t and blocks until
// the user confirms or cancels. It returns the index of the chosen row
// in m.Rows, or -1 with an error. Navigation: arrows (ESC [ A/B), j/k,
// wrap-around, disabled rows skipped; Enter confirms; Esc and Ctrl+C
// return ErrCanceled (the caller maps that to exit 130). The menu is
// cleared on exit and replaced by a one-line outcome
// ("selected: <label>" / "canceled").
//
// When the terminal cannot host the framed UI (VT probe or raw-mode
// failure), Select degrades to a plain numbered-list prompt with no
// escape codes. The terminal size is queried once per call.
func Select(ctx context.Context, t Terminal, m SelectModel) (int, error) {
	if len(m.Rows) == 0 {
		return -1, errors.New("tui: select: no rows")
	}
	cursor := firstEnabled(m.Rows)
	if cursor < 0 {
		return -1, errors.New("tui: select: no selectable rows")
	}

	vt := interactiveCapable(t)
	restore := func() {}
	if vt {
		r, err := t.MakeRaw()
		if err != nil {
			vt = false // cooked input still serves the numbered list
		} else {
			restore = r
		}
	}
	defer restore() // exactly once on every exit path

	if !vt {
		return selectPlain(ctx, t, m)
	}

	cols, rowsTerm := terminalSize(t)
	men := &menu{
		t: t, p: painter{t: t},
		title: m.Title, subtitle: m.Subtitle, footer: m.Footer,
		rows: m.Rows, cursor: cursor,
		cols: cols, rowsTerm: rowsTerm,
	}
	idx, runErr := men.run(ctx)
	outcome := ""
	switch {
	case runErr == nil:
		outcome = "selected: " + m.Rows[idx].Label
	case errors.Is(runErr, ErrCanceled):
		outcome = "canceled"
	}
	_ = men.p.clear()
	finErr := men.p.finish(outcome)
	if runErr != nil {
		return -1, runErr
	}
	if finErr != nil {
		return -1, finErr
	}
	return idx, nil
}

// selectPlain runs the numbered-list fallback: the rows are printed
// once with numbers and the user answers with digits + Enter (cooked
// line editing and echo belong to the terminal). Esc, Ctrl+C, and an
// empty Enter cancel.
func selectPlain(ctx context.Context, t Terminal, m SelectModel) (int, error) {
	out := newPlainOut(t)
	cols, _ := terminalSize(t)
	for _, ln := range plainLines(m.Title, m.Subtitle, m.Rows, nil, cols) {
		if err := out.line(ln); err != nil {
			return -1, err
		}
	}
	for {
		if err := out.prompt(fmt.Sprintf("Enter a number (1-%d), Esc cancels: ", len(m.Rows))); err != nil {
			return -1, err
		}
		s, err := readPlainLine(ctx, t, out, keepDigits)
		if err != nil {
			return -1, err
		}
		if s == "" {
			if err := out.close("canceled"); err != nil {
				return -1, err
			}
			return -1, ErrCanceled
		}
		n, perr := strconv.Atoi(s)
		switch {
		case perr != nil || n < 1 || n > len(m.Rows):
			if err := out.line("invalid choice: " + s); err != nil {
				return -1, err
			}
		case m.Rows[n-1].Disabled:
			if err := out.line(fmt.Sprintf("row %d is not selectable", n)); err != nil {
				return -1, err
			}
		default:
			if err := out.close("selected: " + m.Rows[n-1].Label); err != nil {
				return -1, err
			}
			return n - 1, nil
		}
	}
}
