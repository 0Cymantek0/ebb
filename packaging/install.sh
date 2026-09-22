#!/bin/sh
# install.sh — Ebb installer for Linux (amd64).
#
# Target of:  curl -fsSL https://get.ebb.dev | sh
#
# Downloads the ebb-v<version>-linux-amd64.tar.gz release archive AND the
# release SHA256SUMS.txt (the archive FILENAME carries the full tag with
# the leading v, exactly as scripts/release.sh names it; the URL's
# download/<tag>/ directory also keeps the v), verifies the archive SHA256
# against the matching SHA256SUMS line (always — no unverified download is
# ever executed or installed), installs the binary to ~/.local/bin, prints
# exact PATH fix instructions if that directory is not on PATH, and prints
# the installed version.
#
# The tar member is ebb-linux-amd64 (archive-member name defined by
# scripts/release.sh); it is installed as ~/.local/bin/ebb.
#
# POSIX sh (dash-safe), set -eu. Proxy: curl/wget honor https_proxy /
# HTTPS_PROXY environment variables automatically. Test/mirror hooks:
#   EBB_TAG=v0.1.0            skip latest-release resolution (pin a tag)
#   EBB_DOWNLOAD_BASE=<url>   override the release download base URL
#                             (default: <repo>/releases/download); the
#                             checksum gate applies unchanged.
#   EBB_BIN_DIR=<dir>         override the install directory
#                             (default: ~/.local/bin)
set -eu

# The public repository is github.com/0Cymantek0/ebb (owner filled 2026-09-22).
REPO_URL='https://github.com/0Cymantek0/ebb'

die() {
	echo "install.sh: error: $*" >&2
	exit 1
}

step() { echo "==> $*"; }

# ---- platform gate ----------------------------------------------------------

os=$(uname -s)
arch=$(uname -m)

case $os in
	Darwin*)
		echo 'macOS is not supported in this release (D039)' >&2
		exit 1
		;;
esac

case $os:$arch in
	Linux:x86_64) plat=linux-amd64 ;;
	*)
		die "unsupported platform '$os:$arch' (this release publishes linux/amd64 only)"
		;;
esac

# ---- tooling ----------------------------------------------------------------

fetch() { # fetch <url> <outfile>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die 'need curl or wget to download'
	fi
}

if command -v sha256sum >/dev/null 2>&1; then
	sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die 'need sha256sum or shasum to verify the download'
fi

# ---- resolve the release tag ------------------------------------------------

if [ -n "${EBB_TAG:-}" ]; then
	tag=$EBB_TAG
else
	step "resolving latest release of $REPO_URL"
	if command -v curl >/dev/null 2>&1; then
		tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
			"$REPO_URL/releases/latest") || die 'could not reach github.com to resolve the latest release'
	else
		# wget cannot report the redirect target; use the JSON API instead.
		api_json=$(wget -q -O - "https://api.github.com/repos${REPO_URL#https://github.com}/releases/latest") \
			|| die 'could not reach the GitHub API to resolve the latest release'
		tag=$(printf '%s' "$api_json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
	fi
	tag=${tag##*/}   # .../tag/v0.1.0 -> v0.1.0
	[ -n "$tag" ] || die 'could not determine the latest release tag'
fi

# Anchored release-tag gate (the same regex family scripts/release.sh and
# install.ps1 use). A shell `case` GLOB must not be used here: a glob '*'
# matches '/' too, so a traversal tag like 'v0.1.0/../../attacker' would
# pass and flow into the download URL and the local output filename.
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' \
	|| die "invalid release tag '$tag' (want vMAJOR.MINOR.PATCH[-suffix], e.g. v0.1.0)"

download_base=${EBB_DOWNLOAD_BASE:-$REPO_URL/releases/download}
# The archive FILENAME carries the full tag with the leading v
# (ebb-v0.1.0-linux-amd64.tar.gz), exactly as scripts/release.sh names it.
archive="ebb-$tag-$plat.tar.gz"

# ---- download + verify + install --------------------------------------------

tmpdir=$(mktemp -d) || die 'mktemp failed'
trap 'rm -rf "$tmpdir"' EXIT
cd "$tmpdir"

step "downloading $download_base/$tag/$archive"
fetch "$download_base/$tag/$archive" "$archive"

step "downloading $download_base/$tag/SHA256SUMS.txt"
fetch "$download_base/$tag/SHA256SUMS.txt" SHA256SUMS.txt

step 'verifying SHA256 against SHA256SUMS.txt'
# Tolerate both "hash  file" (GNU/Linux) and "hash *file" (binary-mode
# marker, e.g. Git Bash sha256sum/shasum) line spellings. The archive name
# is regex-escaped before interpolation so the pattern below can only match
# a SUMS line naming EXACTLY this file — a tag carrying regex
# metacharacters (belt-and-braces with the anchored gate above) must never
# widen the match to a different archive's line.
arch_pat=$(printf '%s' "$archive" | sed 's/[^0-9A-Za-z_-]/\\&/g')
expected=$(sed -n "s/^\([0-9A-Fa-f]\{64\}\)[[:space:]]*\*\?[[:space:]]*\($arch_pat\)\$/\1/p" SHA256SUMS.txt)
if [ -z "$expected" ]; then
	die "no SHA256SUMS line matches '$archive'; refusing"
fi
actual=$(sha "$archive")
if [ "$actual" != "$expected" ]; then
	rm -f "$archive" SHA256SUMS.txt
	die "checksum mismatch for $archive
        expected $expected
        actual   $actual
        the download was discarded; nothing was installed"
fi
step 'checksum OK'

bin_dir=${EBB_BIN_DIR:-$HOME/.local/bin}
step "installing to $bin_dir/ebb"
tar -xzf "$archive"
[ -f "ebb-$plat" ] || die "archive member ebb-$plat not found in $archive (release layout changed?)"
mkdir -p "$bin_dir"
cp "ebb-$plat" "$bin_dir/ebb"
chmod 0755 "$bin_dir/ebb"

# ---- PATH guidance + version ------------------------------------------------

case ":$PATH:" in
	*":$bin_dir:"*) ;;
	*)
		cat >&2 <<EOF

note: $bin_dir is not on your PATH. Fix it with:

    export PATH="$bin_dir:\$PATH"

and make it permanent by adding that line to ~/.profile (or ~/.bashrc).
EOF
		;;
esac

step 'installed version:'
"$bin_dir/ebb" version
