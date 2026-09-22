# Packaging & distribution runbook (D038)

Everything a maintainer needs to turn a tagged release built by
`scripts/release.sh` into published winget / scoop / install-script
channels. These files are TEMPLATES with unambiguous placeholders —
nothing here is publishable until the placeholders are filled.

## What lives here

| File | Channel | Role |
|---|---|---|
| `winget/ebb.yaml` | winget (version manifest) | root of the 3-file winget-pkgs manifest set |
| `winget/ebb.installer.yaml` | winget (installer manifest) | portable exe inside a zip (`NestedInstallerType: portable`) |
| `winget/ebb.locale.en-US.yaml` | winget (defaultLocale manifest) | metadata; carries the pending license |
| `scoop/ebb.json` | scoop | manifest + `checkver`/`autoupdate` against GitHub releases |
| `install.ps1` | `irm https://get.ebb.dev/ps1 \| iex` | Windows user-scope installer, always checksum-gated |
| `install.sh` | `curl -fsSL https://get.ebb.dev \| sh` | Linux amd64 installer, always checksum-gated |
| `validate.sh` | — | syntax/structure checks for all of the above |

## Ground truth: artifact contract (from scripts/release.sh)

Release assets attached to a GitHub release tag `vX.Y.Z`:

```
ebb-vX.Y.Z-windows-amd64.zip      # archive MEMBER inside: ebb-windows-amd64.exe
ebb-vX.Y.Z-linux-amd64.tar.gz     # archive MEMBER inside: ebb-linux-amd64
SHA256SUMS.txt                    # "<sha256>  <archive-name>" per line, over ARCHIVES
```

The archive FILENAME carries the FULL tag including the leading `v`
(`ebb-v0.1.0-windows-amd64.zip`), and so does the release download URL's
`.../download/v0.1.0/` directory — installers and manifests must spell both
exactly this way (this was audit finding D1: every consumer once dropped the
`v` from the filename and 404'd against a real release).

The member name inside an archive has NO version in it — manifests and
installers must reference `ebb-windows-amd64.exe` / `ebb-linux-amd64`
exactly. Only windows/amd64 and linux/amd64 are published (no darwin, no
arm64); do not add installer entries for platforms `release.sh` does not
build.

## Placeholders you MUST fill at publish time

Search for these markers; every occurrence is deliberate:

| Marker | Where | Replace with |
|---|---|---|
| `OWNER` (in `github.com/OWNER/ebb`) | all files except install.sh comments; scoop JSON cannot carry comments, hence README | the real GitHub owner/org slug. The repo had **no git remote** when these templates were written — set one first (`git remote add origin https://github.com/<owner>/ebb.git`) |
| `0000...0` (64 zeros) | winget installer `InstallerSha256`; scoop `url` hash | real SHA256 of the archive (from the release `SHA256SUMS.txt` line) |
| `License: __PENDING__` | winget locale manifest | the SPDX identifier once the maintainer decides; also add `LicenseUrl`. **Do not invent a license.** |
| `"license": "Unknown"` | scoop JSON (JSON has no comments, so the placeholder lives here) | the license identifier once decided |
| `Ebb.Ebb` / `Publisher: Ebb` | winget manifests | keep, or change to the real publisher identity — must be consistent across all three files and unique in winget-pkgs |
| `0.1.0` / `v0.1.0` | everywhere | the version being published |

`packaging/validate.sh` re-checks structure and flags remaining
placeholders (it prints them as UNFILLED, which is the expected state
before a release — not an error).

## Release order

1. **Tag**: commit, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
2. **Build**: `scripts/release.sh vX.Y.Z` (clean tree required). Produces
   `dist/vX.Y.Z/` per the artifact contract above.
3. **Attach**: upload the two archives and `SHA256SUMS.txt` to the GitHub
   release for the tag. Do not rename anything.
4. **Fill templates**: replace placeholders (table above) — hash values
   come straight from `dist/vX.Y.Z/SHA256SUMS.txt`.
5. **Test the installers for real**, against the published release:
   ```sh
   packaging/install.sh                                        # linux (CI or a VM/container)
   pwsh packaging/install.ps1                                  # windows
   # tamper test (both must refuse): corrupt SHA256SUMS.txt on a
   # local mock server and point the installers at it — see
   # EBB_DOWNLOAD_BASE / -RepoUrl / -Version hooks below.
   ```
6. **Publish channels** (below).
7. **get.ebb.dev** must serve the installers (below).

## winget-pkgs submission flow

1. Verify the manifest version is current against
   <https://learn.microsoft.com/en-us/windows/package-manager/package/manifest>
   and the schema docs in
   <https://github.com/microsoft/winget-pkgs/tree/master/doc/manifest/schema>
   (templates here use ManifestVersion 1.12.0, current as of 2026-09).
2. Preferred: install winget-create and let it submit the PR:
   ```powershell
   winget install wingetcreate
   wingetcreate new  # paste the zip URL; it hashes and templates for you
   ```
   Then reconcile with `packaging/winget/` (keep these files as the
   in-repo source of truth) and answer its submission prompts.
   Manual alternative: fork `microsoft/winget-pkgs`, add
   `manifests/e/Ebb/Ebb/X.Y.Z/{Ebb.Ebb.yaml,Ebb.Ebb.installer.yaml,Ebb.Ebb.locale.en-US.yaml}`,
   open a PR; bot validation checks schema, URLs and hashes.
3. The zip + `NestedInstallerType: portable` +
   `NestedInstallerFiles[0].PortableCommandAlias: ebb` combination is
   what gives users an `ebb` command from the versioned member name.
   `PortableCommandAlias` is only schema-valid inside a
   `NestedInstallerFiles` entry (verified against the 1.12.0 installer
   spec).
4. New versions = new folder + new PR; update these templates in the
   same change so they never drift.

## scoop flow (community "extras"-style bucket or own bucket)

`scoop/ebb.json` carries `checkver` + `autoupdate`:

- `checkver.regex` scrapes the latest tag from the repo's releases page
  (`tag/vX.Y.Z` → `X.Y.Z`, so `$version` has no leading `v`).
- `autoupdate.architecture.64bit.url` rebuilds the asset URL as
  `.../download/v$version/ebb-v$version-windows-amd64.zip`.
- `autoupdate.hash.url` fetches the release `SHA256SUMS.txt` and the
  regex captures the hash from the matching line — scoop stays
  checksum-gated automatically.
- `bin: [["ebb-windows-amd64.exe","ebb"]]` renames the archive member
  to the `ebb` shim.

To publish: add `ebb.json` to a bucket (your own
`github.com/<owner>/scoop-bucket`, or PR to a community bucket once the
license is decided — extras requires a known license). Verify with
`scoop checkup` / `scoop install ebb` and `scoop info ebb`.

## get.ebb.dev

`get.ebb.dev` and `get.ebb.dev/ps1` must serve (redirect or serve
directly — a 302 to raw.githubusercontent.com is fine):

- `https://get.ebb.dev/ps1` -> raw URL of `packaging/install.ps1` on the
  default branch of the public repo
- `https://get.ebb.dev`     -> raw URL of `packaging/install.sh`

The scripts themselves only talk to `github.com` / `api.github.com` /
`objects.githubusercontent.com`; the short domain is pure convenience
URL. Keep TLS mandatory. The owner of the domain decides the DNS/hosting
— until it exists, install docs must point at the GitHub raw URLs.

## Installer behavior matrix (enforced in both scripts)

| Situation | install.sh | install.ps1 |
|---|---|---|
| linux/amd64 + good checksum | install to `~/.local/bin/ebb`, run `ebb version` | n/a |
| windows/amd64 + good checksum | n/a | install to `%LOCALAPPDATA%\Programs\ebb\ebb.exe`, User PATH, run `ebb version` |
| darwin (any arch) | refuse: `macOS is not supported in this release (D039)`, exit 1 | n/a |
| any other OS/arch | refuse with platform message, exit 1 | refuse via GitHub artifact absence / version check |
| SHA256 mismatch / missing SHA256SUMS line | delete download, exit 1, nothing installed | delete download, exit 1, nothing installed |
| `~/.local/bin` not on PATH | print exact `export PATH=...` fix lines | n/a (installs into User PATH automatically) |

Test hooks (documented for CI): `install.sh` honors `EBB_TAG`,
`EBB_DOWNLOAD_BASE`, `EBB_BIN_DIR`; `install.ps1` honors `-Version`,
`-Destination`, `-RepoUrl`. The checksum gate applies in all cases.

## Validating the templates

```sh
bash packaging/validate.sh
```

Invoke it with `bash`, not `sh` (the shebang already says bash): the script
uses `BASH_SOURCE` and `set -o pipefail`, so a POSIX `sh` (dash on Debian)
dies with `Bad substitution` under the `sh packaging/validate.sh` spelling
(audit finding V2). On Linux CI, also install PowerShell (`pwsh`) first —
without a PowerShell engine the install.ps1 parser check honestly fails,
and a green run needs it.

Checks: POSIX syntax of `install.sh` (`sh -n`, plus `dash -n` when
available), PowerShell parser round-trip of `install.ps1` (pwsh and, if
installed, Windows PowerShell 5.1), JSON validity of `scoop/ebb.json`,
and structural key-presence checks on the winget YAML files. The YAML
checks are grep-level: they verify required keys exist, not full schema
conformance — full conformance is checked by winget-create /
winget-pkgs PR validation at submission time.

## Unsigned binaries (honest trust story)

The release binaries are **not signed**. There is no Authenticode
signing in the pipeline yet, and this section documents what that means
instead of leaving it unsaid:

- **What the SHA256SUMS gate does:** both installers and both package
  managers verify the downloaded archive's SHA256 against the release's
  `SHA256SUMS.txt` BEFORE anything is extracted, executed, or put on PATH.
  This catches corrupted mirrors, truncated downloads, and any byte-level
  tampering between the release page and the user's machine.
- **What it does NOT do:** `SHA256SUMS.txt` is fetched from the SAME
  origin (the GitHub release) as the archive itself. It is a transport
  integrity check, not an independent trust root — a compromise of the
  release channel (a hostile tag push, a seized publisher account, a
  tampered `get.ebb.dev`) serves a self-consistent archive+sums pair and
  defeats the gate **by design**. The actual trust root today is the
  TLS-protected GitHub channel plus the publisher identity behind it.
- **SmartScreen / Mark-of-the-Web (Windows):** the zip route (`curl` a
  zip, or download-and-extract from the release page) applies the zone
  identifier (MOTW) to the downloaded archive, and Windows extraction
  flows propagate it to the extracted `ebb.exe`; a first Explorer-launched
  run can therefore hit a SmartScreen "unknown publisher" warning. The
  `irm … | iex` route runs the installer entirely in memory (no MOTW on
  the script itself); the binary it installs is checksum-gated but
  unsigned. winget and scoop soften the UX (their own hash gates,
  no SmartScreen prompt of this shape) but inherit the same-origin trust
  property above.
- **Signing plans:** Authenticode signing of the Windows binary is NOT
  yet in place (no cert story exists yet). When it lands, the signature
  becomes the publisher-identity root and `SHA256SUMS.txt` remains the
  transport integrity layer. Until then, users who want to pin trust
  should verify hashes out-of-band against the release page over an
  authenticated session.
