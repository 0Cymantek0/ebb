package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// ChecklistModel describes one multi-select checklist (the `ebb
// reclaim` group picker).
type ChecklistModel struct {
	Title    string
	Subtitle string
	Rows     []Row
	// Initial is the pre-checked state (reclaim: rebuildable groups
	// pre-checked). Nil or empty starts unchecked. Entries on disabled
	// rows are ignored: disabled rows always render and report
	// unchecked. Its length, when non-zero, must equal len(Rows).
	Initial []bool
	// Footer holds key hints rendered below the frame.
	Footer []string
}

// Checklist shows a framed multi-select checklist on t and blocks
// until the user confirms or cancels. It returns the final checked
// state (one bool per row), or nil with an error. Navigation matches
// Select (arrows/j/k, wrap-around, disabled rows skipped and never
// toggleable); Space toggles the current row, `a` toggles every
// enabled row, Enter confirms, Esc/Ctrl+C return ErrCanceled with a
// nil (zero-value) state. On exit the frame is cleared and a one-line
// summary ("confirmed: N of M selected") replaces it.
//
// The numbered fallback runs when the terminal cannot host the framed
// UI: numbers toggle rows (the list is reprinted so the checkboxes
// stay visible), `a` toggles all, an empty line confirms.
func Checklist(ctx context.Context, t Terminal, m ChecklistModel) ([]bool, error) {
	if len(m.Initial) != 0 && len(m.Initial) != len(m.Rows) {
		return nil, errors.New("tui: checklist: Initial length does not match Rows")
	}
	checked := make([]bool, len(m.Rows))
	for i := range checked {
		checked[i] = i < len(m.Initial) && m.Initial[i] && !m.Rows[i].Disabled
	}

	vt := interactiveCapable(t)
	restore := func() {}
	if vt {
		r, err := t.MakeRaw()
		if err != nil {
			vt = false
		} else {
			restore = r
		}
	}
	defer restore() // exactly once on every exit path

	if !vt {
		return checklistPlain(ctx, t, m, checked)
	}

	cols, rowsTerm := terminalSize(t)
	men := &menu{
		t: t, p: painter{t: t},
		title: m.Title, subtitle: m.Subtitle, footer: m.Footer,
		rows: m.Rows, cursor: firstEnabled(m.Rows), checked: checked,
		prefix: func(i int) string {
			if checked[i] {
				return "[X] "
			}
			return "[ ] "
		},
		cols: cols, rowsTerm: rowsTerm,
	}
	_, runErr := men.run(ctx)
	outcome := ""
	switch {
	case runErr == nil:
		outcome = checklistSummary(checked)
	case errors.Is(runErr, ErrCanceled):
		outcome = "canceled"
	}
	_ = men.p.clear()
	finErr := men.p.finish(outcome)
	if runErr != nil {
		return nil, runErr
	}
	if finErr != nil {
		return nil, finErr
	}
	return checked, nil
}

func checklistSummary(checked []bool) string {
	n := 0
	for _, c := range checked {
		if c {
			n++
		}
	}
	return fmt.Sprintf("confirmed: %d of %d selected", n, len(checked))
}

// checklistPlain runs the numbered-list fallback: entering a number
// toggles that row (the list is reprinted after every change), `a`
// toggles all enabled rows, an empty line confirms, Esc cancels.
func checklistPlain(ctx context.Context, t Terminal, m ChecklistModel, checked []bool) ([]bool, error) {
	out := newPlainOut(t)
	cols, _ := terminalSize(t)
	prefixes := make([]string, len(m.Rows))
	printList := func() error {
		for i := range prefixes {
			if checked[i] {
				prefixes[i] = "[X] "
			} else {
				prefixes[i] = "[ ] "
			}
		}
		for _, ln := range plainLines(m.Title, m.Subtitle, m.Rows, prefixes, cols) {
			if err := out.line(ln); err != nil {
				return err
			}
		}
		return nil
	}
	if err := printList(); err != nil {
		return nil, err
	}
	for {
		if err := out.prompt("Toggle a number, a = all, Enter confirms, Esc cancels: "); err != nil {
			return nil, err
		}
		s, err := readPlainLine(ctx, t, out, keepDigitsOrAll)
		if err != nil {
			return nil, err
		}
		switch s {
		case "":
			if err := out.close(checklistSummary(checked)); err != nil {
				return nil, err
			}
			return checked, nil
		case "a", "A":
			toggleAllState(checked, m.Rows)
			if err := printList(); err != nil {
				return nil, err
			}
		default:
			n, perr := strconv.Atoi(s)
			switch {
			case perr != nil || n < 1 || n > len(m.Rows):
				if err := out.line("invalid choice: " + s); err != nil {
					return nil, err
				}
			case m.Rows[n-1].Disabled:
				if err := out.line(fmt.Sprintf("row %d cannot be toggled", n)); err != nil {
					return nil, err
				}
			default:
				checked[n-1] = !checked[n-1]
				if err := printList(); err != nil {
					return nil, err
				}
			}
		}
	}
}
