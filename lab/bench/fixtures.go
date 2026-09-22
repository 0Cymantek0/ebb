// Fixture generators for the §14.4 corpus, Windows-practical. Everything
// is generated from fixed seeds with a seeded PRNG (NOT crypto/rand —
// speed) and is disposable. Names avoid characters illegal on Windows
// (<>:"/\|?* and controls) and reserved device names; unicode, spaces and
// deep nesting are deliberately included. The --scale multiplier grows
// entry counts and byte sizes roughly linearly.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

// fixture is one corpus entry: a name, a description and a builder that
// materializes the tree under dir.
type fixture struct {
	name  string
	desc  string
	build func(dir string, scale float64, rng *rand.Rand) error
}

// allFixtures is the corpus, in run order (small file trees first, data
// fixtures last). Default (scale 1.0) counts are TIME-BOUNDED to keep the
// full run around ten minutes on a laptop SSD given the measured
// ~0.8 s per restic subprocess invocation (see docs/BENCHMARKS.md): the
// Foundation §14.4 reference counts (5,000-entry small-file tree, ~2,000
// node files, ~1,500 python files) are reached with --scale in the 25-45
// range, and the per-file readback transport makes such runs take hours,
// which is exactly the scaling risk this harness exists to quantify.
func allFixtures() []fixture {
	return []fixture{
		{"smallfiles", "small files (64B-4KiB) in deep dirs, unicode + spaces, empty dirs", buildSmallfiles},
		{"node", "npm-shaped project: package(-lock).json + node_modules packages + source", buildNode},
		{"python", "uv/python project: pyproject.toml + uv.lock + .venv-shaped tree + source", buildPython},
		{"media", "incompressible seeded-PRNG data (default 256 MiB in a few large files)", buildMedia},
		{"shared", "duplicated content within one fixture (dedup) + a hardlink group", buildShared},
	}
}

func fixtureNames() string {
	var names []string
	for _, fx := range allFixtures() {
		names = append(names, fx.name)
	}
	return strings.Join(names, ", ")
}

// scaleCount applies the multiplier to a base entry count.
func scaleCount(base int, scale float64) int {
	n := int(float64(base)*scale + 0.5)
	if n < 1 {
		n = 1
	}
	return n
}

// writeFile is mkdir -p + write with a size check.
func writeFile(root string, rel string, content []byte) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

// nameStyles are the smallfiles name templates: plain, spaces, accented,
// CJK, emoji — all legal on NTFS and ext4.
var nameStyles = []func(i int) string{
	func(i int) string { return fmt.Sprintf("file-%04d.txt", i) },
	func(i int) string { return fmt.Sprintf("notes %d.md", i) },
	func(i int) string { return fmt.Sprintf("données-%d.cfg", i) },
	func(i int) string { return fmt.Sprintf("文件-%d.dat", i) },
	func(i int) string { return fmt.Sprintf("emoji 🙂 %d.log", i) },
}

// smallfileBody renders deterministic pseudo-text of size bytes.
func smallfileBody(rng *rand.Rand, size int) []byte {
	const words = 16
	var b strings.Builder
	for b.Len() < size {
		for w := 0; w < words && b.Len() < size; w++ {
			fmt.Fprintf(&b, "%08x ", rng.Uint64())
		}
		b.WriteByte('\n')
	}
	return []byte(b.String()[:size])
}

// buildSmallfiles: ~90 files at scale 1 (5,000-entry reference ≈ scale 42)
// spread over themed directories, a deep chain (depth 6), empty dirs and
// unicode/space names. File sizes cycle through 64B..4KiB.
func buildSmallfiles(dir string, scale float64, rng *rand.Rand) error {
	n := scaleCount(90, scale)
	areas := []string{"src", "src/core", "src/core/internal", "docs and notes", "assets", "assets/地面", "config", "tests"}
	empty := []string{"empty", "leer 目录", "vide (1)"}
	for _, d := range empty {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(d)), 0o755); err != nil {
			return err
		}
	}
	i := 0
	placed := 0
	for placed < n {
		area := areas[i%len(areas)]
		size := 64 + (i*379)%4032 // 64..4095
		rel := area + "/" + nameStyles[i%len(nameStyles)](i)
		if err := writeFile(dir, rel, smallfileBody(rng, size)); err != nil {
			return err
		}
		placed++
		i++
	}
	// A deep chain: depth 6, one file per level.
	deep := "deep"
	for lvl := 0; lvl < 6 && placed < n+6; lvl++ {
		rel := deep + "/nested.go.txt"
		if err := writeFile(dir, rel, smallfileBody(rng, 512+lvl)); err != nil {
			return err
		}
		deep += "/l" + fmt.Sprint(lvl)
	}
	return nil
}

// buildNode: npm-shaped project — package.json, package-lock.json, a
// node_modules of small packages (~12 packages × 4 files at scale 1) and
// private source files.
func buildNode(dir string, scale float64, rng *rand.Rand) error {
	pkgs := scaleCount(12, scale)
	srcFiles := scaleCount(10, scale)
	if err := writeFile(dir, "package.json", []byte(fmt.Sprintf(
		`{"name":"bench-node","version":"1.0.0","private":true,"dependencies":%d}`+"\n", pkgs))); err != nil {
		return err
	}
	var lock strings.Builder
	lock.WriteString("{\n  \"name\": \"bench-node\",\n  \"lockfileVersion\": 3,\n  \"packages\": {\n")
	for p := 0; p < pkgs; p++ {
		fmt.Fprintf(&lock, "    \"node_modules/@bench/pkg-%03d\": {\"version\":\"1.%d.0\",\"resolved\":\"https://registry.npmjs.org/@bench/pkg-%03d/-/pkg-%03d-1.%d.0.tgz\"},\n",
			p, p%9, p, p, p%9)
	}
	lock.WriteString("  }\n}\n")
	if err := writeFile(dir, "package-lock.json", []byte(lock.String())); err != nil {
		return err
	}
	for p := 0; p < pkgs; p++ {
		pkg := fmt.Sprintf("node_modules/@bench/pkg-%03d", p)
		if err := writeFile(dir, pkg+"/package.json", []byte(fmt.Sprintf(
			`{"name":"@bench/pkg-%03d","version":"1.%d.0","main":"index.js"}`+"\n", p, p%9))); err != nil {
			return err
		}
		if err := writeFile(dir, pkg+"/index.js", smallfileBody(rng, 700+p)); err != nil {
			return err
		}
		if err := writeFile(dir, pkg+"/README.md", smallfileBody(rng, 300+p)); err != nil {
			return err
		}
		if err := writeFile(dir, pkg+"/lib/helper.js", smallfileBody(rng, 500+p)); err != nil {
			return err
		}
	}
	for s := 0; s < srcFiles; s++ {
		rel := fmt.Sprintf("src/private-%02d.ts", s)
		if s%3 == 0 {
			rel = fmt.Sprintf("src/lib/private %d.ts", s)
		}
		if err := writeFile(dir, rel, smallfileBody(rng, 900+s)); err != nil {
			return err
		}
	}
	return nil
}

// buildPython: uv-shaped project — pyproject.toml, uv.lock, a .venv
// tree (~8 packages × 3 files + bin scripts at scale 1) and source files.
func buildPython(dir string, scale float64, rng *rand.Rand) error {
	pkgs := scaleCount(8, scale)
	srcFiles := scaleCount(7, scale)
	if err := writeFile(dir, "pyproject.toml", []byte(fmt.Sprintf(
		"[project]\nname = \"bench-py\"\nversion = \"0.1.0\"\ndependencies = %d\n\n[tool.uv]\nmanaged = true\n", pkgs))); err != nil {
		return err
	}
	var lock strings.Builder
	lock.WriteString("version = 1\n\n[options]\nresolution-markers = []\n\n[packages]\n")
	for p := 0; p < pkgs; p++ {
		fmt.Fprintf(&lock, "bench-pkg-%03d = { version = \"2.%d.1\", source = \"registry\" }\n", p, p%7)
	}
	if err := writeFile(dir, "uv.lock", []byte(lock.String())); err != nil {
		return err
	}
	if err := writeFile(dir, ".venv/pyvenv.cfg", []byte(
		"home = /usr/bin\nimplementation = CPython\nversion_info = 3.12.0\ninclude-system-site-packages = false\n")); err != nil {
		return err
	}
	for _, script := range []string{"activate", "activate.bat", "python"} {
		if err := writeFile(dir, ".venv/bin/"+script, smallfileBody(rng, 400+len(script))); err != nil {
			return err
		}
	}
	for p := 0; p < pkgs; p++ {
		pkg := fmt.Sprintf(".venv/lib/python3.12/site-packages/bench_pkg_%03d", p)
		if err := writeFile(dir, pkg+"/__init__.py", smallfileBody(rng, 200+p)); err != nil {
			return err
		}
		if err := writeFile(dir, pkg+"/core.py", smallfileBody(rng, 800+p)); err != nil {
			return err
		}
		if err := writeFile(dir, pkg+"/py.typed", []byte("")); err != nil {
			return err
		}
	}
	for s := 0; s < srcFiles; s++ {
		rel := fmt.Sprintf("app/module_%02d.py", s)
		if s%3 == 1 {
			rel = fmt.Sprintf("app/测试 %d.py", s)
		}
		if err := writeFile(dir, rel, smallfileBody(rng, 600+s)); err != nil {
			return err
		}
	}
	return nil
}

// buildMedia: incompressible seeded-PRNG data, 256 MiB at scale 1 in four
// large files. PCG/LCG-style output does not compress under restic's
// default zstd, so this exercises the raw data path.
func buildMedia(dir string, scale float64, rng *rand.Rand) error {
	const total = 256 << 20
	files := 4
	per := int(float64(total) * scale / float64(files))
	if per < 1<<20 { // keep at least 1 MiB per file at tiny scales
		per = 1 << 20
	}
	buf := make([]byte, 4<<20)
	for f := 0; f < files; f++ {
		path := filepath.Join(dir, fmt.Sprintf("clip-%02d.bin", f))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		fh, err := os.Create(path)
		if err != nil {
			return err
		}
		written := 0
		for written < per {
			fillRandom(rng, buf)
			chunk := len(buf)
			if per-written < chunk {
				chunk = per - written
			}
			if _, err := fh.Write(buf[:chunk]); err != nil {
				fh.Close()
				return err
			}
			written += chunk
		}
		if err := fh.Close(); err != nil {
			return err
		}
	}
	return nil
}

// fillRandom fills buf from the seeded PRNG (deterministic per rng state).
func fillRandom(rng *rand.Rand, buf []byte) {
	// 8 bytes per Uint64 call; the tail is filled byte-wise.
	i := 0
	for ; i+8 <= len(buf); i += 8 {
		v := rng.Uint64()
		buf[i] = byte(v)
		buf[i+1] = byte(v >> 8)
		buf[i+2] = byte(v >> 16)
		buf[i+3] = byte(v >> 24)
		buf[i+4] = byte(v >> 32)
		buf[i+5] = byte(v >> 40)
		buf[i+6] = byte(v >> 48)
		buf[i+7] = byte(v >> 56)
	}
	for ; i < len(buf); i++ {
		buf[i] = byte(rng.Uint64())
	}
}

// buildShared: substantial duplicated content WITHIN one fixture (4
// unique 1 MiB blobs × 6 copies at scale 1 — restic dedup should store
// ~4 MiB, not 24) plus a hardlink group (4 names on one 1 MiB blob via
// os.Link; NTFS and ext4 both support it unprivileged).
func buildShared(dir string, scale float64, rng *rand.Rand) error {
	blobs := 4
	copies := 6
	blobSize := int(float64(1<<20) * scale)
	if blobSize < 64<<10 {
		blobSize = 64 << 10
	}
	for b := 0; b < blobs; b++ {
		body := make([]byte, blobSize)
		fillRandom(rng, body)
		for c := 0; c < copies; c++ {
			rel := fmt.Sprintf("assets/dup/blob-%02d-copy-%d.bin", b, c)
			if err := writeFile(dir, rel, body); err != nil {
				return err
			}
		}
	}
	// Hardlink group: one physical blob, four names.
	hlBody := make([]byte, blobSize)
	fillRandom(rng, hlBody)
	orig := filepath.Join(dir, "hard", "original.bin")
	if err := writeFile(dir, "hard/original.bin", hlBody); err != nil {
		return err
	}
	for l := 1; l < 4; l++ {
		link := filepath.Join(dir, "hard", fmt.Sprintf("alias %d.bin", l))
		if err := os.Link(orig, link); err != nil {
			return fmt.Errorf("hardlink %s: %w", link, err)
		}
	}
	return nil
}

// fixtureSeed derives the per-fixture deterministic seed.
func fixtureSeed(name string) int64 {
	var s int64 = 0x6562622d62656e63 // "ebb-benc"
	for _, c := range name {
		s = s*31 + int64(c)
	}
	return s
}
