// Package card renders `ebb stats --share`'s shareable PNG graphic card
// (Wave 3, task 3C): a fixed 1600x900 dark-theme dashboard snapshot of
// the Developer Space Economy, suitable for pasting into a chat or a PR
// description.
//
// The package is PURE: Render turns an Input into PNG bytes and touches
// nothing else — no clock, no randomness, no filesystem (WriteFile is
// the thin persistence wrapper). The same Input always renders
// byte-identical bytes; the footer date comes from Input.AsOf (set by
// the caller, never minted here) precisely so that holds.
//
// Fonts are the redistributable Go fonts (golang.org/x/image/font/
// gofont: Go Bold, Go Regular, Go Mono) parsed once from their embedded
// TTF data — no font files on disk, no licensing surface beyond the
// x/image dependency already in go.mod.
//
// Honesty rules inherited from the stats core: unknown metrics render
// as "—" chips, never fake zeros; a degenerate all-zero donut renders
// an empty ring with a "no data yet" note; text is measured and
// truncated (or wrapped, bounded) to its region so nothing can overflow
// or overlap the fixed canvas.
package card

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	"github.com/0Cymantek0/ebb/internal/stats"
)

// Canvas geometry in FINAL pixels. All drawing happens on a 2x
// supersampled bitmap that is box-downsampled at the end, so circles
// and diagonals come out crisp without a font engine doing subpixel
// tricks.
const (
	cardWidth  = 1600
	cardHeight = 900
	ss         = 2 // supersample factor
	margin     = 64
)

// Palette: deep charcoal base, one teal accent for the wordmark/hero,
// and three harmonious data colors for the donut (teal/amber/violet).
var (
	colBackground = color.RGBA{R: 22, G: 24, B: 29, A: 255} // deep charcoal
	colPanel      = color.RGBA{R: 31, G: 35, B: 43, A: 255} // raised card
	colText       = color.RGBA{R: 232, G: 234, B: 239, A: 255}
	colMuted      = color.RGBA{R: 154, G: 160, B: 172, A: 255}
	colFaint      = color.RGBA{R: 105, G: 111, B: 124, A: 255}
	colAccent     = color.RGBA{R: 45, G: 212, B: 191, A: 255}  // teal (reclaimed)
	colRestored   = color.RGBA{R: 245, G: 158, B: 11, A: 255}  // amber
	colParked     = color.RGBA{R: 139, G: 124, B: 246, A: 255} // violet
)

// Input is the frozen render request (Wave 3 contract).
type Input struct {
	// Metrics is the dashboard model (internal/stats.Metrics).
	Metrics stats.Metrics
	// Comparison is the quirky scale sentence shown in the quote card.
	Comparison stats.Comparison
	// Path is the output file path for WriteFile (ignored by Render).
	Path string
	// Background is unused in v1 (kept for the frozen API shape; keep 0).
	Background int64
	// AsOf is the caller-minted footer date (YYYY-MM-DD). Empty omits
	// the date — Render never consults a clock, so identical Inputs
	// (including AsOf) render identical bytes.
	AsOf string
}

// Render draws the card and returns PNG bytes. It writes no files.
func Render(in Input) ([]byte, error) {
	boldF, regF, monoF, err := goFonts()
	if err != nil {
		return nil, fmt.Errorf("card: loading fonts: %w", err)
	}
	fc, err := newFaces(boldF, regF, monoF)
	if err != nil {
		return nil, fmt.Errorf("card: rasterizing fonts: %w", err)
	}

	p := &painter{img: image.NewRGBA(image.Rect(0, 0, cardWidth*ss, cardHeight*ss))}
	draw.Draw(p.img, p.img.Rect, &image.Uniform{colBackground}, image.Point{}, draw.Src)
	m := in.Metrics

	// ---- 1. header: "ebb" wordmark + small-caps label -----------------
	wordmark := "ebb"
	p.textS(margin, 128, fc.wordmark, wordmark, colAccent)
	wmW := stringWidth(fc.wordmark, wordmark)
	p.rectS(margin, 148, margin+wmW, 153, colAccent) // accent underline
	label := spacedUpper("developer space economy", 7)
	p.textTruncS(margin+wmW+34, 128, label, fc.label, colMuted,
		cardWidth-margin-(margin+wmW+34))

	// ---- 2. hero headline: "<X> <unit> SAVED" --------------------------
	heroValue := clean(stats.HumanBytes(m.LifetimeReclaimedBytes))
	heroTail := "SAVED"
	// "SAVED" keeps its color slot; the value must leave room for it.
	maxValue := cardWidth - 2*margin - stringWidth(fc.hero, heroTail) - 24
	heroValue = truncateWidth(fc.hero, heroValue, maxValue)
	vw := stringWidth(fc.hero, heroValue)
	p.textS(margin, 268, fc.hero, heroValue, colText)
	p.textS(margin+vw+24, 268, fc.hero, heroTail, colAccent)
	p.textTruncS(margin, 318, "lifetime reclaimed through ebb", fc.heroSub, colMuted,
		cardWidth-2*margin)

	// ---- 3. donut over the three byte metrics + legend ----------------
	// The donut shows the three BYTE-backed metrics only. Active
	// workspaces are deliberately a text stat in the legend, NOT a
	// donut share: a live workspace has no recorded byte size anywhere
	// in the journal (workspace summaries carry a size only for parked
	// workspaces — the latest park event's bytes_out), so giving it a
	// ring segment would require inventing bytes. A count is the honest
	// rendering.
	donutCx, donutCy, rOut, rIn := 246, 506, 142, 92
	slices := []donutSlice{
		{share: positive(m.LifetimeReclaimedBytes), col: colAccent},
		{share: positive(m.LifetimeRestoredBytes), col: colRestored},
		{share: positive(m.CurrentlyParkedBytes), col: colParked},
	}
	p.donutS(donutCx, donutCy, rOut, rIn, slices, colFaint)
	if sumShares(slices) <= 0 {
		p.textCenteredS(donutCx, donutCy, "no data yet", fc.legendLabel, colFaint, rIn-14)
	}

	legendX, legendRight := 430, 836
	legend := []struct {
		label string
		value string
		col   color.RGBA
	}{
		{"RECLAIMED", stats.HumanBytes(m.LifetimeReclaimedBytes), colAccent},
		{"RESTORED", stats.HumanBytes(m.LifetimeRestoredBytes), colRestored},
		{"PARKED (ON ICE)", stats.HumanBytes(m.CurrentlyParkedBytes), colParked},
	}
	for i, row := range legend {
		base := 402 + i*48
		p.chipS(legendX, base-23, row.col)
		p.textTruncS(legendX+42, base, row.label, fc.legendLabel, colMuted,
			legendRight-160-(legendX+42))
		p.textRightTruncS(legendRight, base, row.value, fc.legendValue, colText,
			150)
	}
	// Count-only rows (no byte size exists — see the comment above the
	// slices): active workspaces and the total invocation count.
	p.hlineS(legendX, 522, legendRight, colFaint)
	p.textTruncS(legendX, 560, "ACTIVE WORKSPACES", fc.legendLabel, colMuted,
		300)
	p.textRightTruncS(legendRight, 560, strconv.Itoa(max0(m.ActiveWorkspaces)),
		fc.legendValue, colText, 150)
	p.textTruncS(legendX, 608, "EBB KEYSTROKES", fc.legendLabel, colMuted, 300)
	p.textRightTruncS(legendRight, 608,
		groupComma(m.TotalInvocations)+" to date", fc.legendValue, colText, 190)

	// ---- 4. stat row: 2x2 tiles ----------------------------------------
	tiles := []struct{ label, value string }{
		{"SPACE EFFICIENCY", efficiencyLabel(m.SpaceEfficiencyRatio)},
		{"CLEAN DESK STREAK", streakLabel(m.CleanDeskStreakDays)},
		{"ZOMBIE EXORCISED", stats.HumanBytes(m.ZombieBytesExorcised)},
		{"SSD WEAR SAVED", stats.HumanBytes(m.EstimatedSSDWearSaved)},
	}
	const tileW, tileH, gap = 324, 144, 8
	for i, t := range tiles {
		x0 := 880 + (i%2)*(tileW+gap)
		y0 := 356 + (i/2)*(tileH+gap)
		p.panelS(x0, y0, x0+tileW, y0+tileH, 14, colPanel)
		p.textTruncS(x0+24, y0+40, t.label, fc.statLabel, colMuted, tileW-48)
		p.textTruncS(x0+24, y0+106, t.value, fc.statValue, colText, tileW-48)
	}

	// ---- 5. badges: hoarding grade chip + command trophy ---------------
	const bx0, bx1, by0, by1 = 1016, cardWidth - margin, 676, 828
	p.panelS(bx0, by0, bx1, by1, 14, colPanel)
	rows := []struct {
		label, value string
		valueCol     color.RGBA
	}{
		{"HOARDING SCORE", hoardingBadge(m.HoardingScore), colText},
		{"TOP COMMAND", topCommandBadge(m.TopCommands), colText},
		{"EBB KEYSTROKES", groupComma(m.TotalInvocations) + " to date", colText},
	}
	for i, r := range rows {
		base := 714 + i*48
		p.textTruncS(bx0+24, base, r.label, fc.chipLabel, colMuted, 170)
		p.textRightTruncS(bx1-24, base, r.value, fc.chipValue, r.valueCol,
			bx1-bx0-48-190)
	}

	// ---- 6. comparison quote card ---------------------------------------
	const qx0, qx1 = margin, 1000
	p.panelS(qx0, 676, qx1, 828, 14, colPanel)
	if in.Comparison.Text != "" {
		quote := `"` + clean(in.Comparison.Text) + `"`
		lines := wrapClamp(fc.quote, quote, qx1-qx0-88, 3)
		for i, ln := range lines {
			p.textTruncS(qx0+44, 716+i*38, ln, fc.quote, colText, qx1-qx0-88)
		}
		if in.Comparison.Subject != "" {
			p.textRightTruncS(qx1-24, 818, "scale reference: "+clean(in.Comparison.Subject),
				fc.attribution, colFaint, qx1-qx0-88)
		}
	} else {
		p.textTruncS(qx0+44, 716, "(no comparison yet — the journal has nothing to scale)",
			fc.quote, colFaint, qx1-qx0-88)
	}

	// ---- 7. footer -------------------------------------------------------
	p.textTruncS(margin, 872, "ebb // disk space for builders", fc.footer, colFaint,
		900)
	if in.AsOf != "" {
		p.textRightTruncS(cardWidth-margin, 872, clean(in.AsOf), fc.footer, colFaint, 220)
	}

	// Downsample 2x (box average) and encode.
	final := downscale2x(p.img)
	var buf bytes.Buffer
	if err := png.Encode(&buf, final); err != nil {
		return nil, fmt.Errorf("card: encoding PNG: %w", err)
	}
	return buf.Bytes(), nil
}

// WriteFile renders the card and writes it to Input.Path (mode 0600 on
// creation). Overwriting an existing file is allowed — the intended
// rerun is same-day regeneration of the same card.
func WriteFile(in Input) error {
	b, err := Render(in)
	if err != nil {
		return err
	}
	if err := os.WriteFile(in.Path, b, 0o600); err != nil {
		return fmt.Errorf("card: writing %s: %w", in.Path, err)
	}
	return nil
}

// ---- fonts -----------------------------------------------------------------

var (
	fontsOnce sync.Once
	fontBold  *opentype.Font
	fontReg   *opentype.Font
	fontMono  *opentype.Font
	fontsErr  error
)

// goFonts parses the embedded Go fonts once.
func goFonts() (*opentype.Font, *opentype.Font, *opentype.Font, error) {
	fontsOnce.Do(func() {
		if fontBold, fontsErr = opentype.Parse(gobold.TTF); fontsErr != nil {
			return
		}
		if fontReg, fontsErr = opentype.Parse(goregular.TTF); fontsErr != nil {
			return
		}
		fontMono, fontsErr = opentype.Parse(gomono.TTF)
	})
	return fontBold, fontReg, fontMono, fontsErr
}

// faces bundles one render's sized faces (sizes in FINAL pixels; the
// faces themselves are created at size*ss on the supersampled bitmap).
type faces struct {
	wordmark, hero, statValue, legendValue, chipValue, quote       font.Face // bold
	label, heroSub, statLabel, legendLabel, chipLabel, attribution font.Face // regular
	footer                                                         font.Face // mono
}

func newFaces(bold, reg, mono *opentype.Font) (*faces, error) {
	mk := func(f *opentype.Font, size int) (font.Face, error) {
		return opentype.NewFace(f, &opentype.FaceOptions{
			Size: float64(size * ss), DPI: 72, Hinting: font.HintingNone,
		})
	}
	var fc faces
	var err error
	pairs := []struct {
		f    *opentype.Font
		size int
		dst  *font.Face
	}{
		{bold, 64, &fc.wordmark}, {bold, 108, &fc.hero},
		{bold, 52, &fc.statValue}, {bold, 32, &fc.legendValue},
		{bold, 30, &fc.chipValue}, {bold, 32, &fc.quote},
		{reg, 26, &fc.label}, {reg, 28, &fc.heroSub},
		{reg, 22, &fc.statLabel}, {reg, 24, &fc.legendLabel},
		{reg, 22, &fc.chipLabel}, {reg, 22, &fc.attribution},
		{mono, 22, &fc.footer},
	}
	for _, pr := range pairs {
		if *pr.dst, err = mk(pr.f, pr.size); err != nil {
			return nil, err
		}
	}
	return &fc, nil
}

// ---- painter ----------------------------------------------------------------

// painter draws on the supersampled bitmap. Coordinates given to its
// methods are FINAL-scale pixels; the *S suffix helpers convert.
type painter struct {
	img *image.RGBA
}

func s(v int) int { return v * ss }

func (p *painter) textS(x, y int, f font.Face, str string, col color.Color) {
	d := &font.Drawer{
		Dst: p.img, Src: image.NewUniform(col), Face: f,
		Dot: fixed.P(s(x), s(y)),
	}
	d.DrawString(clean(str))
}

// textTruncS draws str left-aligned at x, truncated with "..." so it
// never exceeds maxW final pixels.
func (p *painter) textTruncS(x, y int, str string, f font.Face, col color.Color, maxW int) {
	p.textS(x, y, f, truncateWidth(f, clean(str), s(maxW)), col)
}

// textRightTruncS right-aligns str at x (the RIGHT edge), truncated to
// maxW.
func (p *painter) textRightTruncS(x, y int, str string, f font.Face, col color.Color, maxW int) {
	str = truncateWidth(f, clean(str), s(maxW))
	w := stringWidth(f, str)
	p.textS(x-w/ss, y, f, str, col)
}

// textCenteredS centers str on cx within maxW final pixels.
func (p *painter) textCenteredS(cx, cy int, str string, f font.Face, col color.Color, maxW int) {
	str = truncateWidth(f, clean(str), s(maxW))
	w := stringWidth(f, str) // supersampled px
	p.textS(cx-w/(2*ss), cy, f, str, col)
}

func (p *painter) rectS(x0, y0, x1, y1 int, col color.RGBA) {
	draw.Draw(p.img, image.Rect(s(x0), s(y0), s(x1), s(y1)), &image.Uniform{col}, image.Point{}, draw.Src)
}

func (p *painter) hlineS(x0, y, x1 int, col color.RGBA) {
	p.rectS(x0, y, x1, y+1, col)
}

// panelS fills a rounded rectangle.
func (p *painter) panelS(x0, y0, x1, y1, rad int, col color.RGBA) {
	rad = s(rad)
	if rad*2 > x1-x0 || rad*2 > y1-y0 {
		rad = min(s(x1-x0), s(y1-y0)) / 2
	}
	X0, Y0, X1, Y1 := s(x0), s(y0), s(x1), s(y1)
	ix0, iy0, ix1, iy1 := X0+rad, Y0+rad, X1-rad, Y1-rad
	r2 := float64(rad) * float64(rad)
	for y := Y0; y < Y1; y++ {
		cy := clamp(y, iy0, iy1-1)
		for x := X0; x < X1; x++ {
			cx := clamp(x, ix0, ix1-1)
			if dx, dy := x-cx, y-cy; dx*dx+dy*dy <= int(r2) {
				p.img.SetRGBA(x, y, col)
			}
		}
	}
}

// chipS draws one small color square (a legend key).
func (p *painter) chipS(x, y int, col color.RGBA) {
	p.panelS(x, y, x+24, y+24, 6, col)
}

// donutSlice is one ring share (share is a raw byte count; the ring
// geometry normalizes).
type donutSlice struct {
	share float64
	col   color.RGBA
}

func positive(n int64) float64 {
	if n > 0 {
		return float64(n)
	}
	return 0
}

func sumShares(s []donutSlice) float64 {
	var t float64
	for _, v := range s {
		if v.share > 0 {
			t += v.share
		}
	}
	return t
}

// donutS draws the ring at final-scale coordinates. All-zero shares
// render an empty thin ring (ringCol) — never a fake zero segment.
// Segments start at 12 o'clock and run clockwise with a small angular
// gap between neighbors.
func (p *painter) donutS(cx, cy, rOut, rIn int, slices []donutSlice, ringCol color.RGBA) {
	cx, cy, rOut, rIn = s(cx), s(cy), s(rOut), s(rIn)
	total := sumShares(slices)

	type bound struct {
		a0, a1 float64
		col    color.RGBA
	}
	var bounds []bound
	if total > 0 {
		n := 0
		for _, sl := range slices {
			if sl.share > 0 {
				n++
			}
		}
		const gap = 0.035 // radians (~2°) between adjacent slices
		gapTotal := 0.0
		if n > 1 {
			gapTotal = gap * float64(n)
		}
		arcLen := 2*math.Pi - gapTotal
		acc := -math.Pi / 2
		for _, sl := range slices {
			if sl.share <= 0 {
				continue
			}
			w := sl.share / total * arcLen
			bounds = append(bounds, bound{acc, acc + w, sl.col})
			acc += w + gap
		}
	}

	outF, inF := float64(rOut), float64(rIn)
	for y := cy - rOut - 1; y <= cy+rOut+1; y++ {
		for x := cx - rOut - 1; x <= cx+rOut+1; x++ {
			dx, dy := float64(x-cx), float64(y-cy)
			d := math.Hypot(dx, dy)
			if d > outF || d < inF {
				continue
			}
			switch {
			case total <= 0:
				// Empty ring: a thin outline near the outer edge only.
				if d >= outF-3*ss {
					p.img.SetRGBA(x, y, ringCol)
				}
			default:
				rel := math.Atan2(dy, dx) + math.Pi/2
				for rel < 0 {
					rel += 2 * math.Pi
				}
				for i := range bounds {
					if rel >= bounds[i].a0 && rel < bounds[i].a1 {
						p.img.SetRGBA(x, y, bounds[i].col)
						break
					}
				}
				// Pixels inside the inter-slice gaps stay background.
			}
		}
	}
}

// ---- text helpers -------------------------------------------------------------

// stringWidth measures str's advance width on the supersampled bitmap
// (returns supersampled pixels).
func stringWidth(f font.Face, str string) int {
	d := &font.Drawer{Face: f}
	return d.MeasureString(clean(str)).Ceil()
}

// truncateWidth shortens str (rune-safely) with a "..." suffix until it
// fits max (same scale as stringWidth: callers pass s(finalWidth)).
func truncateWidth(f font.Face, str string, max int) string {
	str = clean(str)
	if max <= 0 {
		return ""
	}
	if stringWidth(f, str) <= max {
		return str
	}
	rs := []rune(str)
	lo, hi := 0, len(rs)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if stringWidth(f, string(rs[:mid])+"...") <= max {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo == 0 {
		return "..." // pathological: region smaller than the ellipsis alone
	}
	return string(rs[:lo]) + "..."
}

// wrapClamp greedily word-wraps str to max (supersampled pixels) and
// clamps to at most maxLines lines, the last one ellipsized. A single
// word wider than max is hard-truncated. Always returns 1..maxLines
// lines.
func wrapClamp(f font.Face, str string, max, maxLines int) []string {
	if maxLines < 1 {
		maxLines = 1
	}
	if max <= 0 {
		return []string{"..."}
	}
	words := strings.Fields(clean(str))
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		switch {
		case cur == "":
			cur = w
		case stringWidth(f, cur+" "+w) <= max:
			cur += " " + w
		default:
			lines = append(lines, cur)
			cur = w
		}
		if stringWidth(f, cur) > max {
			lines = append(lines, truncateWidth(f, cur, max))
			cur = ""
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) <= maxLines {
		return lines
	}
	kept := append([]string(nil), lines[:maxLines-1]...)
	tail := strings.Join(lines[maxLines-1:], " ")
	return append(kept, truncateWidth(f, tail, max))
}

// spacedUpper uppercases str and inserts tracking px between runes
// (small-caps label effect without a second font).
func spacedUpper(str string, tracking int) string {
	var b strings.Builder
	for i, r := range strings.ToUpper(clean(str)) {
		if i > 0 {
			b.WriteString(strings.Repeat(" ", tracking))
		}
		b.WriteRune(r)
	}
	return b.String()
}

// clean replaces terminal-control bytes with spaces (drawing hygiene —
// the canvas is data, not a shell, but control runes have no glyphs)
// and strips UTF-8 replacement risk by dropping invalid runes.
func clean(str string) string {
	if !strings.ContainsRune(str, utf8.RuneError) && !hasControl(str) {
		return str
	}
	var b strings.Builder
	b.Grow(len(str))
	for _, r := range str {
		switch {
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		case r == utf8.RuneError:
			// Either a literal U+FFFD or an invalid encoding; drop it.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasControl(str string) bool {
	for i := 0; i < len(str); i++ {
		if c := str[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// ---- value formatters -----------------------------------------------------------

func efficiencyLabel(r float64) string {
	if r > 0 {
		return fmt.Sprintf("%.1fx", r)
	}
	return "—" // unknown ratio (nothing restored yet), never 0.0x
}

func streakLabel(days int) string {
	if days == 1 {
		return "1 day"
	}
	return strconv.Itoa(max0(days)) + " days"
}

// hoardingBadge renders the grade chip text: "A+ · Minimalist" when
// graded, "—" when the rubric could not run (no scan facts).
func hoardingBadge(sc stats.Score) string {
	if sc.Grade == "" {
		return "—"
	}
	if sc.Label == "" {
		return sc.Grade
	}
	return sc.Grade + " · " + clean(sc.Label)
}

// topCommandBadge renders the command trophy: the most-invoked verb
// with its count, or a graceful empty state.
func topCommandBadge(cmds []stats.CommandCount) string {
	if len(cmds) == 0 {
		return "no commands yet"
	}
	top := cmds[0]
	for _, c := range cmds[1:] {
		if c.Count > top.Count {
			top = c
		}
	}
	return clean(top.Command) + " × " + groupComma(top.Count)
}

// groupComma renders n with thousands separators ("2,341"); negative
// values clamp to 0 (counts are never negative in the model).
func groupComma(n int64) string {
	if n < 0 {
		n = 0
	}
	str := strconv.FormatInt(n, 10)
	var parts []string
	for len(str) > 3 {
		parts = append([]string{str[len(str)-3:]}, parts...)
		str = str[:len(str)-3]
	}
	parts = append([]string{str}, parts...)
	return strings.Join(parts, ",")
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- downscale --------------------------------------------------------------------

// downscale2x halves a supersampled bitmap with a 2x2 box average
// (deterministic, allocation-free of any sampling randomness).
func downscale2x(src *image.RGBA) *image.RGBA {
	w, h := src.Rect.Dx()/2, src.Rect.Dy()/2
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			x0, y0 := x*2, y*2
			var r, g, b uint32
			for dy := 0; dy < 2; dy++ {
				for dx := 0; dx < 2; dx++ {
					pr, pg, pb, _ := src.At(x0+dx, y0+dy).RGBA()
					r += pr / 256
					g += pg / 256
					b += pb / 256
				}
			}
			dst.SetRGBA(x, y, color.RGBA{
				R: uint8(r / 4), G: uint8(g / 4), B: uint8(b / 4), A: 255,
			})
		}
	}
	return dst
}
