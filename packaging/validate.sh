#!/usr/bin/env bash
# validate.sh — syntax / structure checks for the packaging templates.
#
# Honest scope: this script verifies SYNTAX (POSIX sh, PowerShell, JSON)
# and STRUCTURE (required keys present in the winget YAML files). YAML is
# NOT schema-validated here — no YAML parser is assumed; winget-pkgs /
# winget-create perform full schema validation at submission time.
#
# Run from anywhere: paths resolve relative to this script.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fails=0
passes=0

pass() { echo "  PASS: $*"; passes=$((passes + 1)); }
fail() { echo "  FAIL: $*" >&2; fails=$((fails + 1)); }
info() { echo "  note: $*"; }

# ---- install.sh: POSIX sh syntax --------------------------------------------

echo "[install.sh]"
if sh -n "$here/install.sh" 2>err.txt; then pass "sh -n (POSIX syntax)"; else fail "sh -n: $(cat err.txt)"; fi
if command -v dash >/dev/null 2>&1; then
	if dash -n "$here/install.sh" 2>err.txt; then pass "dash -n (dash/POSIX syntax)"; else fail "dash -n: $(cat err.txt)"; fi
else
	info "dash not available; sh -n only"
fi
rm -f err.txt

# ---- install.ps1: PowerShell parser round-trip ------------------------------

echo "[install.ps1]"
# Native Windows PowerShell needs a Windows path; MSYS passes /c/... through
# unconverted when embedded in a longer argument, so convert explicitly.
ps_path="$here/install.ps1"
if command -v cygpath >/dev/null 2>&1; then
	ps_path=$(cygpath -w "$ps_path")
fi
ps_parse() { # ps_parse <pwsh-or-powershell>
	local bin=$1
	"$bin" -NoProfile -Command "
		\$errs = \$null
		[void][System.Management.Automation.Language.Parser]::ParseFile('$ps_path', [ref]\$null, [ref]\$errs)
		if (\$errs -and \$errs.Count -gt 0) {
			\$errs | ForEach-Object { Write-Error \$_.Message }
			exit 1
		}
		exit 0
	" 2>ps_err.txt
}
ps_checked=0
for bin in pwsh powershell; do
	if command -v "$bin" >/dev/null 2>&1; then
		ps_checked=$((ps_checked + 1))
		if ps_parse "$bin"; then pass "$bin parser: no syntax errors"; else fail "$bin parser: $(head -5 ps_err.txt)"; fi
	fi
done
rm -f ps_err.txt
[ "$ps_checked" -gt 0 ] || fail "no PowerShell available to parse install.ps1"

# ---- scoop/ebb.json: JSON validity ------------------------------------------

echo "[scoop/ebb.json]"
json_ok=notdone
if command -v python >/dev/null 2>&1; then
	if python -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$here/scoop/ebb.json" 2>err.txt; then
		pass "python json.load: valid JSON"; json_ok=done
	else fail "python json.load: $(cat err.txt)"; fi
elif command -v node >/dev/null 2>&1; then
	if node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$here/scoop/ebb.json" 2>err.txt; then
		pass "node JSON.parse: valid JSON"; json_ok=done
	else fail "node JSON.parse: $(cat err.txt)"; fi
else
	# go fallback: minimal one-off program (repo toolchain is Go)
	tmpgo=$(mktemp -d)
	cat >"$tmpgo/main.go" <<'EOF'
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	var v map[string]any
	if err := json.NewDecoder(f).Decode(&v); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON:", err)
		os.Exit(1)
	}
}
EOF
	if (cd "$tmpgo" && go run . "$here/scoop/ebb.json") 2>err.txt; then
		pass "go encoding/json: valid JSON"; json_ok=done
	else fail "go encoding/json: $(head -3 err.txt)"; fi
	rm -rf "$tmpgo"
fi
rm -f err.txt

# scoop structure: bin mapping renames the archived member to ebb
# (layout-tolerant: "ebb-windows-amd64.exe" and "ebb" may be on one line or
# successive lines of the same JSON array)
if grep -A2 '"ebb-windows-amd64\.exe"' "$here/scoop/ebb.json" | grep -q '"ebb"'; then
	pass "bin maps archive member ebb-windows-amd64.exe -> ebb"
else
	fail "bin mapping [\"ebb-windows-amd64.exe\",\"ebb\"] not found"
fi
for key in version checkver autoupdate; do
	if grep -q "\"$key\"" "$here/scoop/ebb.json"; then pass "key \"$key\" present"; else fail "key \"$key\" missing"; fi
done

# ---- winget YAML: structural key-presence (grep-level, NOT schema validation)

ykey() { # ykey <file> <label> <expected-key-line> (tolerates a leading "- " list marker)
	if grep -Eq "^[[:space:]]*-?[[:space:]]*$3\$" "$here/winget/$1"; then pass "$2: '$3' present"; else fail "$2: '$3' missing"; fi
}

echo "[winget/ebb.yaml] (version manifest)"
ykey ebb.yaml ebb.yaml 'PackageIdentifier: Ebb.Ebb'
ykey ebb.yaml ebb.yaml 'PackageVersion: 0\.1\.0'
ykey ebb.yaml ebb.yaml 'DefaultLocale: en-US'
ykey ebb.yaml ebb.yaml 'ManifestType: version'
ykey ebb.yaml ebb.yaml 'ManifestVersion: 1\.12\.0'

echo "[winget/ebb.installer.yaml] (installer manifest)"
ykey ebb.installer.yaml ebb.installer.yaml 'PackageIdentifier: Ebb.Ebb'
ykey ebb.installer.yaml ebb.installer.yaml 'PackageVersion: 0\.1\.0'
ykey ebb.installer.yaml ebb.installer.yaml 'Architecture: x64'
ykey ebb.installer.yaml ebb.installer.yaml 'InstallerType: zip'
ykey ebb.installer.yaml ebb.installer.yaml 'NestedInstallerType: portable'
ykey ebb.installer.yaml ebb.installer.yaml 'RelativeFilePath: ebb-windows-amd64\.exe'
ykey ebb.installer.yaml ebb.installer.yaml 'PortableCommandAlias: ebb'
ykey ebb.installer.yaml ebb.installer.yaml 'ManifestType: installer'
ykey ebb.installer.yaml ebb.installer.yaml 'ManifestVersion: 1\.12\.0'
if grep -Eq '^[[:space:]]*InstallerUrl: ' "$here/winget/ebb.installer.yaml"; then pass "InstallerUrl present"; else fail "InstallerUrl missing"; fi
if grep -Eq '^[[:space:]]*InstallerSha256: [0-9A-Fa-f]{64}$' "$here/winget/ebb.installer.yaml"; then
	pass "InstallerSha256 is 64 hex chars"
else
	fail "InstallerSha256 is not a 64-hex-char line"
fi

echo "[winget/ebb.locale.en-US.yaml] (defaultLocale manifest)"
ykey ebb.locale.en-US.yaml locale 'PackageIdentifier: Ebb.Ebb'
ykey ebb.locale.en-US.yaml locale 'PackageVersion: 0\.1\.0'
ykey ebb.locale.en-US.yaml locale 'PackageLocale: en-US'
ykey ebb.locale.en-US.yaml locale 'Publisher: Ebb'
ykey ebb.locale.en-US.yaml locale 'PackageName: Ebb'
ykey ebb.locale.en-US.yaml locale 'License: __PENDING__'
ykey ebb.locale.en-US.yaml locale 'ShortDescription: .*'
ykey ebb.locale.en-US.yaml locale 'ManifestType: defaultLocale'
ykey ebb.locale.en-US.yaml locale 'ManifestVersion: 1\.12\.0'

# ---- placeholder inventory (expected UNFILLED before a release) -------------

echo "[placeholders — UNFILLED is the expected pre-release state]"
ph_total=0
for f in winget/ebb.yaml winget/ebb.installer.yaml winget/ebb.locale.en-US.yaml scoop/ebb.json install.ps1 install.sh README.md; do
	n=$(grep -c 'OWNER' "$here/$f" 2>/dev/null || true)
	n=$((n + $(grep -c '0000000000000000000000000000000000000000000000000000000000000000' "$here/$f" 2>/dev/null || true)))
	n=$((n + $(grep -c '__PENDING__\|"Unknown"' "$here/$f" 2>/dev/null || true)))
	if [ "$n" -gt 0 ]; then echo "  UNFILLED: $f: $n placeholder marker(s) (fill at publish — see packaging/README.md)"; fi
	ph_total=$((ph_total + n))
done
info "$ph_total placeholder marker(s) total across packaging/"

# ---- summary ----------------------------------------------------------------

echo
if [ "$fails" -eq 0 ]; then
	echo "validate.sh: OK ($passes checks passed, 0 failed)"
	echo "  YAML checks are grep-level structural checks; full winget schema"
	echo "  validation happens at winget-pkgs submission time."
	exit 0
fi
echo "validate.sh: FAILED ($fails failed, $passes passed)" >&2
exit 1
