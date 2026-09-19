#!/usr/bin/env bash
# scripts/release.sh — reproducible cross-platform release builds for Ebb.
#
# Usage: scripts/release.sh <version>      (e.g. scripts/release.sh v0.1.0)
#
# Builds cmd/ebb for windows/amd64, linux/amd64, darwin/amd64 and
# darwin/arm64 (CGO_ENABLED=0, -trimpath, stripped, version-stamped),
# archives each (zip for Windows, tar.gz otherwise, binary at the
# archive root) and writes SHA256SUMS.txt over the ARCHIVES.
#
# Output: dist/<version>/ebb-<os>-<arch>[.exe] (raw binaries),
#         dist/<version>/ebb-<version>-<os>-<arch>.<zip|tar.gz>,
#         dist/<version>/SHA256SUMS.txt
#
# Works in Git Bash on Windows and on Linux. No PowerShell. The only
# external tools required are go, git, tar and a sha256 utility.
# Windows .zip archives are produced with `git archive` because Git
# Bash ships no `zip` and GNU tar cannot write zip; the same code path
# runs on Linux, so archive bytes do not depend on the build host.
#
# Reproducibility: binaries are (-trimpath, CGO off, fixed version);
# zip entries carry a fixed epoch timestamp; tar members carry fixed
# metadata. Refuses a dirty working tree unless EBB_RELEASE_DIRTY=1.

set -euo pipefail

die() {
	echo "release.sh: error: $*" >&2
	exit 1
}

usage() {
	echo "usage: scripts/release.sh <version>   (e.g. scripts/release.sh v0.1.0)" >&2
}

# ---- arguments -------------------------------------------------------------

[ $# -eq 1 ] || { usage; die "exactly one version argument required, got $#"; }
version=$1
case $version in
	v[0-9]*.[0-9]*.[0-9]*)
		# vMAJOR.MINOR.PATCH with an optional pre-release/build suffix
		# (v0.1.0, v0.1.0-rc.1, v0.1.0-test). Everything else is refused.
		printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' \
			|| die "invalid version '$version' (want vMAJOR.MINOR.PATCH[-suffix], e.g. v0.1.0)"
		;;
	*) die "invalid version '$version' (must start with 'v', e.g. v0.1.0)" ;;
esac

# ---- environment -----------------------------------------------------------

command -v go >/dev/null 2>&1 || die "go not found on PATH"
command -v git >/dev/null 2>&1 || die "git not found on PATH"
command -v tar >/dev/null 2>&1 || die "tar not found on PATH"
if command -v sha256sum >/dev/null 2>&1; then
	sha_tool() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
	sha_tool() { shasum -a 256 "$@"; }
else
	die "no sha256 tool found (need sha256sum or shasum)"
fi

root=$(git rev-parse --show-toplevel) || die "not inside a git repository"
cd "$root"

# ---- dirty-tree gate -------------------------------------------------------

if [ -z "${EBB_RELEASE_DIRTY:-}" ]; then
	if [ -n "$(git status --porcelain)" ]; then
		git status --short >&2
		die "working tree has uncommitted changes; commit them or set EBB_RELEASE_DIRTY=1"
	fi
fi

# ---- deterministic archive helpers ----------------------------------------

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# zip via git archive: Git Bash has no `zip` and GNU tar cannot emit zip,
# but git always can. A temporary index holds exactly the binary; the
# subtree becomes the archive root, and a fixed-date commit object makes
# the embedded entry timestamps (and thus the zip bytes) reproducible.
make_zip() { # make_zip <file-to-embed> <output.zip>
	local embed=$1 out=$2 idx="$tmpdir/index" tree commit
	rm -f "$idx"
	GIT_INDEX_FILE="$idx" git read-tree --empty
	GIT_INDEX_FILE="$idx" git add -f "$embed"
	tree=$(GIT_INDEX_FILE="$idx" git write-tree)
	commit=$(
		GIT_AUTHOR_NAME=ebb-release GIT_AUTHOR_EMAIL=release@ebb.invalid \
		GIT_COMMITTER_NAME=ebb-release GIT_COMMITTER_EMAIL=release@ebb.invalid \
		GIT_AUTHOR_DATE='0 +0000' GIT_COMMITTER_DATE='0 +0000' \
		git commit-tree "$tree" -m "release archive"
	)
	git archive --format=zip --output="$out" "$commit:$(dirname "$embed")"
}

# tar.gz via GNU tar with fixed metadata (sorted names, epoch mtime,
# root ownership). Falls back to plain tar for non-GNU tars (macOS).
make_tgz() { # make_tgz <dir> <file-to-embed> <output.tar.gz>
	local dir=$1 embed=$2 out=$3
	if tar --version 2>/dev/null | head -1 | grep -q 'GNU tar'; then
		tar --format=gnu --sort=name --mtime='1970-01-01 00:00:00Z' \
			--owner=0 --group=0 --numeric-owner -czf "$out" -C "$dir" "$embed"
	else
		tar -czf "$out" -C "$dir" "$embed"
	fi
}

# ---- build -----------------------------------------------------------------

targets="windows/amd64 linux/amd64 darwin/amd64 darwin/arm64"
outroot="dist/$version"
ldflags="-s -w -X main.Version=$version -X ebb/cmd/ebb.Version=$version"

# Note: cmd/ebb is package main; go1.27's linker resolves its package
# path as the literal "main", so -X main.Version is the form that
# actually stamps the binary on this toolchain. The import-path form is
# kept alongside for toolchains that resolve it (an unmatched -X is a
# documented no-op), so both spellings stay valid.

echo "==> ebb release $version"
echo "    go $(go version | awk '{print $3}')  CGO_ENABLED=0 -trimpath"
[ -d "$outroot" ] && { echo "    removing stale $outroot"; rm -rf "$outroot"; }
mkdir -p "$outroot"

for target in $targets; do
	goos=${target%/*}
	goarch=${target#*/}
	bin="ebb-$goos-$goarch"
	ext=""
	[ "$goos" = "windows" ] && { bin="$bin.exe"; ext=".exe"; }

	echo "==> build $goos/$goarch"
	GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 \
		go build -trimpath -ldflags "$ldflags" -o "$outroot/$bin" ./cmd/ebb \
		|| die "build failed for $goos/$goarch"

	echo "==> archive $goos/$goarch"
	archive="$outroot/ebb-$version-$goos-$goarch"
	if [ "$goos" = "windows" ]; then
		make_zip "$outroot/$bin" "$archive.zip" || die "zip failed for $goos/$goarch"
	else
		make_tgz "$outroot" "$bin" "$archive.tar.gz" || die "tar failed for $goos/$goarch"
	fi
done

# ---- checksums over the archives ------------------------------------------

echo "==> checksums"
(
	cd "$outroot"
	: >SHA256SUMS.txt
	for f in *.zip *.tar.gz; do
		[ -e "$f" ] || continue
		sha_tool "$f" >>SHA256SUMS.txt
	done
)

# ---- manifest --------------------------------------------------------------

echo
echo "release $version manifest:"
for target in $targets; do
	goos=${target%/*}
	goarch=${target#*/}
	bin="ebb-$goos-$goarch"
	[ "$goos" = "windows" ] && bin="$bin.exe"
	archive="$outroot/ebb-$version-$goos-$goarch"
	[ "$goos" = "windows" ] && archive="$archive.zip" || archive="$archive.tar.gz"
	printf '  %-42s %10s bytes  (%s/%s)\n' "$outroot/$bin" "$(wc -c <"$outroot/$bin")" "$goos" "$goarch"
	printf '  %-42s %10s bytes\n' "$archive" "$(wc -c <"$archive")"
done
printf '  %-42s %10s bytes\n' "$outroot/SHA256SUMS.txt" "$(wc -c <"$outroot/SHA256SUMS.txt")"
echo
echo "done: $version -> $outroot/"
