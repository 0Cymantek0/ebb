<#
.SYNOPSIS
  Ebb installer for Windows (amd64).

.DESCRIPTION
  Target of:  irm https://get.ebb.dev/ps1 | iex

  Downloads the ebb-v<version>-windows-amd64.zip release archive AND the
  release SHA256SUMS.txt (the archive FILENAME carries the full tag with
  the leading v, exactly as scripts/release.sh names it; the URL's
  download/<tag>/ directory also keeps the v), verifies the archive SHA256
  against the matching SHA256SUMS line (always — no unverified download is
  ever executed or installed), extracts to a user directory (no admin),
  adds it to the User PATH if missing, and prints the installed version.

  The ZIP member is ebb-windows-amd64.exe (archive-member name defined by
  scripts/release.sh); it is installed as ebb.exe.

.PARAMETER Version
  Optional tag override, e.g. -Version v0.1.0. Default: resolve the latest
  release via the GitHub API.

.PARAMETER Destination
  Optional install-directory override (default
  %LOCALAPPDATA%\Programs\ebb).

.PARAMETER RepoUrl
  Optional repository override (default https://github.com/OWNER/ebb — the
  maintainer must replace OWNER when the public repo exists). Primarily a
  test/mirror hook; checksum verification applies unchanged.

.NOTES
  - Works on Windows PowerShell 5.1 and PowerShell 7+ (no modern-only syntax).
  - Honors $env:HTTPS_PROXY (and lowercase https_proxy) with default
    credentials; GITHUB_API_TOKEN is attached ONLY to the api.github.com
    latest-release call if set (never to the -RepoUrl-derived download
    requests; avoids rate limits; never printed).
  - The User PATH is updated through the raw registry value with its
    original type (REG_SZ / REG_EXPAND_SZ) preserved, plus an explicit
    WM_SETTINGCHANGE broadcast.
#>

[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$Destination = '',
    [string]$RepoUrl = 'https://github.com/OWNER/ebb'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# TLS 1.2 for Windows PowerShell 5.1 (no-op where it is already default).
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

function Write-Step([string]$Message) { Write-Host "==> $Message" }
function Die([string]$Message) {
    Write-Host "install.ps1: error: $Message" -ForegroundColor Red
    exit 1
}

# ---- repository + tag -------------------------------------------------------

$RepoUrl = $RepoUrl.TrimEnd('/')
if ($RepoUrl -notmatch '^https?://') {
    Die "RepoUrl must be an http(s) URL, got '$RepoUrl'"
}
# A GitHub RepoUrl enables latest-release resolution via the GitHub API;
# any other base (test mirror) is download-only and requires -Version.
$repo = $null
if ($RepoUrl -match '^https?://github\.com/([^/]+)/([^/]+)') {
    $repo = $Matches[1] + '/' + $Matches[2]
}
$downloadBase = "$RepoUrl/releases/download"

# Download requests (asset zip, SHA256SUMS) carry a plain User-Agent only.
# The GITHUB_API_TOKEN bearer is attached exclusively to the api.github.com
# latest-release call: the download URLs derive from the user-overridable
# -RepoUrl, so a blanket Authorization header would hand the token to any
# mirror host that flag can name.
$Headers = @{ 'User-Agent' = 'ebb-install-ps1' }
$ApiHeaders = @{ 'User-Agent' = 'ebb-install-ps1' }
if ($env:GITHUB_API_TOKEN) {
    $ApiHeaders['Authorization'] = 'Bearer ' + $env:GITHUB_API_TOKEN
}

if (-not $Version) {
    if (-not $repo) {
        Die 'a non-GitHub RepoUrl cannot resolve the latest release; pass -Version <tag>'
    }
    Write-Step "resolving latest release of $repo"
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $ApiHeaders
    } catch {
        Die ("could not query the GitHub API for the latest release: " + $_.Exception.Message + "`n" +
             '        (rate-limited? set GITHUB_API_TOKEN and retry, or pass -Version <tag>)')
    }
    if (-not $release.tag_name) { Die 'GitHub API response carried no tag_name' }
    $Version = [string]$release.tag_name
}
$Version = $Version.Trim()
if ($Version -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$') {
    Die "invalid version tag '$Version' (want vMAJOR.MINOR.PATCH[-suffix])"
}

# ---- proxy ------------------------------------------------------------------

$Proxy = $null
$proxyVar = $env:HTTPS_PROXY
if (-not $proxyVar) { $proxyVar = $env:https_proxy }
if ($proxyVar) {
    $Proxy = $proxyVar
    # Print the proxy HOST only: proxy URLs may embed user:pass credentials,
    # and the host is all the log needs.
    $proxyShown = '(unparsable proxy URL)'
    try { $proxyShown = ([Uri]$Proxy).Host } catch { }
    Write-Step "using proxy $proxyShown"
}

function Get-Url([string]$Url, [string]$OutFile) {
    # -UseBasicParsing avoids the IE-based parser on Windows PowerShell 5.1
    # (it is an ignored no-op on PowerShell 7+).
    $iwr = @{ Uri = $Url; OutFile = $OutFile; Headers = $Headers; UseBasicParsing = $true }
    if ($Proxy) { $iwr.Proxy = $Proxy; $iwr.ProxyUseDefaultCredentials = $true }
    Invoke-WebRequest @iwr
}

# ---- download + verify ------------------------------------------------------

# The archive FILENAME carries the full tag with the leading v
# (ebb-v0.1.0-windows-amd64.zip), matching what scripts/release.sh emits
# into the release's download/v<tag>/ directory.
$zipName = "ebb-$Version-windows-amd64.zip"
$assetUrl = "$downloadBase/$Version/$zipName"
$sumsUrl = "$downloadBase/$Version/SHA256SUMS.txt"

if (-not $Destination) {
    if (-not $env:LOCALAPPDATA) { Die 'LOCALAPPDATA is not set; pass -Destination explicitly' }
    $Destination = Join-Path $env:LOCALAPPDATA 'Programs\ebb'
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("ebb-install-" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipPath = Join-Path $tmp $zipName
$sumsPath = Join-Path $tmp 'SHA256SUMS.txt'

try {
    Write-Step "downloading $assetUrl"
    Get-Url -Url $assetUrl -OutFile $zipPath
    if (-not (Test-Path -LiteralPath $zipPath)) { Die "download produced no file at $zipPath" }

    Write-Step "downloading $sumsUrl"
    Get-Url -Url $sumsUrl -OutFile $sumsPath

    Write-Step 'verifying SHA256 against SHA256SUMS.txt'
    $sums = Get-Content -LiteralPath $sumsPath -ErrorAction SilentlyContinue
    if (-not $sums) { Die 'SHA256SUMS.txt is empty or unreadable' }
    # Tolerate "hash  file" and "hash *file" (binary-mode marker) spellings.
    $match = @($sums | Where-Object { $_ -match ('^\s*[0-9A-Fa-f]{64}\s+\*?' + [regex]::Escape($zipName) + '\s*$') })
    if ($match.Count -ne 1) {
        Die "expected exactly one SHA256SUMS line for $zipName, found $($match.Count); refusing"
    }
    $expected = ($match[0] -split '\s+')[0]
    if (-not $expected) {
        Die "the SHA256SUMS line for $zipName is malformed (no hash field before the filename); refusing"
    }

    $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
    if ($actual -ne $expected) {
        Remove-Item -LiteralPath $zipPath -Force
        Die ("checksum mismatch for $zipName`n" +
             "        expected $expected`n" +
             "        actual   $actual`n" +
             "        the download was discarded; nothing was installed")
    }
    Write-Step 'checksum OK'

    # ---- extract + install (no admin required) -------------------------------

    Write-Step "installing to $Destination"
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $extractDir = Join-Path $tmp 'extracted'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir
    $member = Join-Path $extractDir 'ebb-windows-amd64.exe'
    if (-not (Test-Path -LiteralPath $member)) {
        Die "archive member ebb-windows-amd64.exe not found in $zipName (release layout changed?)"
    }
    Copy-Item -LiteralPath $member -Destination (Join-Path $Destination 'ebb.exe') -Force
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- PATH -------------------------------------------------------------------
# The User PATH is read and written through the RAW registry value, not the
# .NET environment API: [Environment]::GetEnvironmentVariable('Path','User')
# EXPANDS %VAR% entries of a REG_EXPAND_SZ value at read time, and
# SetEnvironmentVariable always writes REG_SZ — a read-modify-write over that
# API flattens every %JAVA_HOME%-style entry to a literal and permanently
# downgrades the type. Reading with DoNotExpandEnvironmentNames and writing
# back with the ORIGINAL RegistryValueKind preserves both bytes and type.
# (SetEnvironmentVariable's WM_SETTINGCHANGE broadcast is lost with raw
# writes, so it is sent explicitly below after a write.)

$envKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
if ($null -eq $envKey) { Die 'could not open HKCU\Environment for the User PATH update' }
try {
    $userPath = ''
    $pathKind = [Microsoft.Win32.RegistryValueKind]::ExpandString
    if ($envKey.GetValueNames() -contains 'Path') {
        $pathKind = $envKey.GetValueKind('Path')
        $userPath = [string]$envKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    $onPath = @($userPath -split ';' | Where-Object { $_ -ne '' }) |
        Where-Object { $_.TrimEnd('\') -ieq $Destination.TrimEnd('\') }
    if (-not $onPath) {
        Write-Step "adding $Destination to the User PATH"
        $envKey.SetValue('Path', ($userPath.TrimEnd(';') + ';' + $Destination).TrimStart(';'), $pathKind)
        # Broadcast WM_SETTINGCHANGE so new processes (and Explorer) pick up
        # the PATH change without a logoff. HWND_BROADCAST, SMTO_ABORTIFHUNG.
        try {
            if (-not ('EbbInstall.Native' -as [type])) {
                Add-Type -Namespace EbbInstall -Name Native -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
            }
            $settingChangeResult = [UIntPtr]::Zero
            [void][EbbInstall.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$settingChangeResult)
        } catch { }
    } else {
        Write-Step "$Destination is already on the User PATH"
    }
} finally {
    $envKey.Close()
}
# Session PATH: plain case-insensitive SEGMENT compare (never a -like
# wildcard pattern — a destination containing []/* would misjudge it).
$sessionHas = @($env:Path -split ';' | Where-Object { $_ -ne '' }) |
    Where-Object { $_.TrimEnd('\') -ieq $Destination.TrimEnd('\') }
if (-not $sessionHas) {
    $env:Path = $env:Path + ';' + $Destination   # make `ebb` usable this session
}

# ---- report -----------------------------------------------------------------

$ebb = Join-Path $Destination 'ebb.exe'
Write-Host ''
Write-Host "installed: $ebb"
# Honest shadowing check: show which ebb actually wins on PATH — an earlier
# entry with a stale ebb.exe would silently shadow the fresh install.
$resolved = @((Get-Command ebb -CommandType Application -ErrorAction SilentlyContinue) | ForEach-Object { $_.Source })
if ($resolved.Count -gt 0 -and ($resolved[0] -ine $ebb)) {
    Write-Host "note: 'ebb' currently resolves to $($resolved[0]) -- an earlier PATH entry shadows the fresh install" -ForegroundColor Yellow
} elseif ($resolved.Count -gt 0) {
    Write-Host "ebb resolves on PATH as: $($resolved[0])"
}
try {
    Write-Step 'installed version:'
    & $ebb version
} catch {
    Write-Host "note: could not run '$ebb version' from this session" -ForegroundColor Yellow
    # A checksum-valid archive whose member is not runnable is a FAILED
    # install (publisher-side error), not a warning: scripts and CI wrapping
    # this installer must see a non-zero exit code.
    Die "the installed binary did not pass the 'ebb version' smoke run; treating this as a failed install"
}
Write-Host ''
Write-Host 'ebb is on the user PATH; open a NEW terminal and run:  ebb doctor'
exit 0
