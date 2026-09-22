#!/usr/bin/env bash
# scripts/release.sh — reproducible cross-platform release builds for Ebb.
#
# Usage: scripts/release.sh <version>      (e.g. scripts/release.sh v0.1.0)
#
# Builds cmd/ebb for the target matrix below (default windows/amd64
# and linux/amd64 — the platforms Ebb builds for today), with
# CGO_ENABLED=0, -trimpath, stripped, version-stamped binaries;
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
# but git always can. A temporary index stages exactly the binary at the
# tree root, a fixed-date commit object sets the entry timestamps, and
# the resulting archive bytes are reproducible for identical inputs.
# (1980-01-01 is the oldest timestamp the zip DOS date field encodes.)
# -buildvcs=false (below) is what keeps that property true across commits
# and dirty trees: without it, Go stamps vcs.revision/vcs.modified into
# the binary's build info, so the SAME source content built at a different
# commit (or with a dirty tree) hashes differently and the release
# SHA256SUMS drift. The release tag -> commit mapping is recorded by git
# itself; the binary does not need a second copy. (Found by rebuilding
# v0.1.0-alpha after manifest-only commits: the hash changed although no
# Go source had.)
make_zip() { # make_zip <file-to-embed> <basename-in-archive> <output.zip>
	local embed=$1 base=$2 out=$3 idx="$tmpdir/index" blob tree commit
	rm -f "$idx"
	blob=$(git hash-object -w "$embed") || die "hash-object failed for $embed"
	tree=$(
		GIT_INDEX_FILE="$idx" git read-tree --empty &&
		GIT_INDEX_FILE="$idx" git update-index --add --cacheinfo "100755,$blob,$base" &&
		GIT_INDEX_FILE="$idx" git write-tree
	) || die "building archive tree failed for $embed"
	[ -n "$tree" ] || die "write-tree returned no tree for $embed"
	commit=$(
		GIT_AUTHOR_NAME=ebb-release GIT_AUTHOR_EMAIL=release@ebb.invalid \
		GIT_COMMITTER_NAME=ebb-release GIT_COMMITTER_EMAIL=release@ebb.invalid \
		GIT_AUTHOR_DATE='1980-01-01T00:00:00+00:00' \
		GIT_COMMITTER_DATE='1980-01-01T00:00:00+00:00' \
		git commit-tree "$tree" -m "release archive"
	) || die "commit-tree failed while archiving $embed"
	[ -n "$commit" ] || die "commit-tree returned no commit for $embed"
	git archive --format=zip --output="$out" "$commit"
}

# tar.gz via GNU tar with fixed metadata (sorted names, epoch mtime,
# root ownership, explicit 755 so the umask never strips the executable
# bit from the stored mode). Falls back to plain tar for non-GNU tars
# (macOS).
make_tgz() { # make_tgz <dir> <file-to-embed> <output.tar.gz>
	local dir=$1 embed=$2 out=$3
	if tar --version 2>/dev/null | head -1 | grep -q 'GNU tar'; then
		tar --format=gnu --sort=name --mtime='1970-01-01 00:00:00Z' \
			--owner=0 --group=0 --numeric-owner --mode=755 \
			-czf "$out" -C "$dir" "$embed"
	else
		tar -czf "$out" -C "$dir" "$embed"
	fi
}

# ---- build -----------------------------------------------------------------

# Default target matrix: the platforms Ebb actually builds for today.
# darwin/* is deliberately absent: internal/platform has windows and
# linux adapters only (README: "macOS is unsupported") and a darwin
# build does not compile. Override with EBB_RELEASE_TARGETS (space-
# separated GOOS/GOARCH pairs) once a darwin platform layer lands; a
# configured target that fails to build fails the release.
targets=${EBB_RELEASE_TARGETS:-windows/amd64 linux/amd64}
outroot="dist/$version"
ldflags="-s -w -X github.com/0Cymantek0/ebb/internal/version.Version=$version"

# Version stamping is single-sourced: internal/version is an ordinary
# (non-main) package, so go1.27's linker resolves its import path
# normally and the -X above reliably stamps the build version every
# surface reads (`ebb version` output, lifecycle manifests/receipts,
# capsule metadata threaded through the CLI). The former dual
# "-X main.Version -X github.com/0Cymantek0/ebb/cmd/ebb.Version" spelling is gone: cmd/ebb no
# longer carries a version variable.

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
		go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$outroot/$bin" ./cmd/ebb \
		|| die "build failed for $goos/$goarch"

	echo "==> archive $goos/$goarch"
	archive="$outroot/ebb-$version-$goos-$goarch"
	if [ "$goos" = "windows" ]; then
		make_zip "$outroot/$bin" "$bin" "$archive.zip" || die "zip failed for $goos/$goarch"
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
