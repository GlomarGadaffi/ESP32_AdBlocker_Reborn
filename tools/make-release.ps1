<#
.SYNOPSIS
    Collects the per-board build artifacts into release/ and writes manifest.json.

.DESCRIPTION
    Reads version.txt for the version, then for each supported board copies the
    four flashable images out of that board's build directory into release/ under
    stable, board- and version-qualified names, and writes release/manifest.json
    describing them.

    The offsets and the flash mode/freq/size are parsed out of each build's own
    flash_args rather than hardcoded here, so if the partition table or flash
    settings change this script follows automatically.

    manifest.json is what docs/flasher/index.html consumes: it fetches the
    manifest from the latest GitHub Release, picks the entry for the detected
    board, and flashes each part at its offset.

    Board IDs must match the ADBLOCK_BOARD_TAG values in CMakeLists.txt — they
    are what the firmware stamps into esp_app_desc_t.version ("<semver>+<board>")
    and what the flasher reads back off the flash to identify the board.

    Nothing is uploaded; the gh command to create the release is printed at the
    end for you to run.

.PARAMETER Version
    Override the version. Defaults to the contents of version.txt.

.PARAMETER OutDir
    Output directory. Defaults to release/ (gitignored).

.EXAMPLE
    .\tools\make-release.ps1
#>
[CmdletBinding()]
param(
    [string] $Version,
    [string] $OutDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot

if (-not $Version) {
    $versionFile = Join-Path $RepoRoot 'version.txt'
    if (-not (Test-Path $versionFile)) { throw "version.txt not found at $versionFile" }
    $Version = (Get-Content $versionFile -TotalCount 1).Trim()
}
if ([string]::IsNullOrWhiteSpace($Version)) { throw 'Version is empty.' }

if (-not $OutDir) { $OutDir = Join-Path $RepoRoot 'release' }

# Board id -> display name + build directory. Board ids are the tags baked into
# esp_app_desc_t.version by CMakeLists.txt; keep the two lists in sync.
$Boards = [ordered]@{
    't-eth-elite'      = @{ Name = 'LilyGO T-ETH-Elite';    BuildDir = 'build' }
    'waveshare-s3-eth' = @{ Name = 'Waveshare ESP32-S3-ETH'; BuildDir = 'build-waveshare' }
}

# Map a flash_args source path to the role the flasher uses to decide which
# parts an "app only" flash needs.
function Get-PartRole {
    param([string] $SourcePath)
    switch -Wildcard ($SourcePath) {
        '*bootloader*'      { return 'bootloader' }
        '*partition*table*' { return 'partition-table' }
        '*ota_data*'        { return 'ota-data' }
        default             { return 'app' }
    }
}

# Parse a build's flash_args into the flash settings line and the offset/file pairs.
function Read-FlashArgs {
    param([string] $Path)

    $settings = $null
    $parts = @()

    foreach ($rawLine in (Get-Content -LiteralPath $Path)) {
        $line = $rawLine.Trim()
        if (-not $line) { continue }

        if ($line.StartsWith('--')) {
            # e.g. "--flash-mode dio --flash-freq 80m --flash-size 16MB"
            $settings = @{}
            $tokens = $line -split '\s+'
            for ($i = 0; $i -lt $tokens.Count - 1; $i++) {
                switch ($tokens[$i]) {
                    '--flash-mode' { $settings['mode'] = $tokens[$i + 1] }
                    '--flash-freq' { $settings['freq'] = $tokens[$i + 1] }
                    '--flash-size' { $settings['size'] = $tokens[$i + 1] }
                }
            }
            continue
        }

        # e.g. "0x20000 dns-sink.bin"
        if ($line -match '^(0[xX][0-9a-fA-F]+|\d+)\s+(\S.*)$') {
            # Capture both groups up front: the hex test below runs another
            # -match, which would clobber $Matches before we read group 2.
            $offsetText = $Matches[1]
            $sourceText = $Matches[2].Trim()

            $offset = if ($offsetText.StartsWith('0x') -or $offsetText.StartsWith('0X')) {
                [Convert]::ToInt64($offsetText.Substring(2), 16)
            } else {
                [int64] $offsetText
            }
            $parts += [pscustomobject]@{
                Offset = $offset
                Source = $sourceText
            }
        }
    }

    if (-not $settings) { throw "No --flash-* settings line found in $Path" }
    if ($parts.Count -eq 0) { throw "No offset/file entries found in $Path" }

    return [pscustomobject]@{ Settings = $settings; Parts = $parts }
}

# ── Secrets guard ─────────────────────────────────────────────────────────
# CONFIG_ADBLOCK_WIFI_SSID/PASSWORD are compiled into the image as the
# first-boot NVS seed. A developer's own sdkconfig usually carries real
# credentials, and the 1.2.0 LilyGo release shipped with the author's home
# Wi-Fi password inside the .bin. Refuse to package if either build's
# sdkconfig has a non-empty value, and grep every app image for the values
# regardless, so a stale build can't sneak through either.
$secretPatterns = @()
foreach ($cfg in @("$RepoRoot\sdkconfig", "$RepoRoot\sdkconfig.waveshare")) {
    if (-not (Test-Path $cfg)) { continue }
    foreach ($line in Get-Content $cfg) {
        if ($line -match '^CONFIG_ADBLOCK_WIFI_(SSID|PASSWORD)="(.+)"$') {
            throw "$cfg has $($Matches[1]) set to a non-empty value. Blank it (CONFIG_ADBLOCK_WIFI_SSID=`"`" / _PASSWORD=`"`"), rebuild, then package. The boards keep their Wi-Fi in NVS."
        }
        if ($line -match '^CONFIG_ADBLOCK_WIFI_PASSWORD="(.+)"' -and $Matches[1].Length -gt 0) { $secretPatterns += $Matches[1] }
    }
}

Write-Host "Packaging release $Version" -ForegroundColor Cyan
Write-Host "  repo:   $RepoRoot"
Write-Host "  output: $OutDir"
Write-Host ''

if (Test-Path $OutDir) {
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$manifestBoards = [ordered]@{}
$flashSettings = $null

foreach ($boardId in $Boards.Keys) {
    $board = $Boards[$boardId]
    $buildDir = Join-Path $RepoRoot $board.BuildDir
    $flashArgsPath = Join-Path $buildDir 'flash_args'

    if (-not (Test-Path $flashArgsPath)) {
        throw "Missing $flashArgsPath — build $boardId first (see README 'Build and flash')."
    }

    Write-Host "$boardId ($($board.Name)) from $($board.BuildDir)/" -ForegroundColor Yellow

    $flashArgs = Read-FlashArgs -Path $flashArgsPath

    # All supported boards share a partition table and flash settings; if that
    # ever stops being true the manifest's single "flash" block needs to move
    # into the per-board entries.
    if ($null -eq $flashSettings) {
        $flashSettings = $flashArgs.Settings
    } else {
        foreach ($key in @('mode', 'freq', 'size')) {
            if ($flashSettings[$key] -ne $flashArgs.Settings[$key]) {
                throw "Flash setting '$key' differs between builds ($($flashSettings[$key]) vs $($flashArgs.Settings[$key])); the manifest carries one shared 'flash' block."
            }
        }
    }

    $manifestParts = @()

    foreach ($part in $flashArgs.Parts) {
        $sourcePath = Join-Path $buildDir ($part.Source -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path $sourcePath)) {
            throw "flash_args references $($part.Source) but $sourcePath does not exist."
        }

        $role = Get-PartRole -SourcePath $part.Source

        # ota_data_initial.bin keeps its full stem; the others get the role name.
        $stem = switch ($role) {
            'bootloader'      { 'bootloader' }
            'partition-table' { 'partition-table' }
            'ota-data'        { 'ota_data_initial' }
            default           { 'app' }
        }

        $destName = "$boardId-$Version-$stem.bin"
        $destPath = Join-Path $OutDir $destName
        Copy-Item -LiteralPath $sourcePath -Destination $destPath -Force

        $size = (Get-Item -LiteralPath $destPath).Length
        Write-Host ("  0x{0:x} {1,-20} {2,9:N0} bytes  <- {3}" -f $part.Offset, $role, $size, $part.Source)

        $manifestParts += [ordered]@{
            offset = $part.Offset
            file   = $destName
            role   = $role
            size   = $size
        }
    }

    $manifestBoards[$boardId] = [ordered]@{
        name  = $board.Name
        parts = $manifestParts
    }

    Write-Host ''
}

$manifest = [ordered]@{
    version = $Version
    boards  = $manifestBoards
    flash   = [ordered]@{
        size = $flashSettings['size']
        mode = $flashSettings['mode']
        freq = $flashSettings['freq']
    }
}

# -Depth must cover manifest > boards > board > parts > part; the default of 2
# would serialise the nested arrays as "System.Object[]".
$json = $manifest | ConvertTo-Json -Depth 8

# No BOM: the flasher page parses this with response.json(), which chokes on one.
$manifestPath = Join-Path $OutDir 'manifest.json'
[System.IO.File]::WriteAllText($manifestPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Wrote $manifestPath" -ForegroundColor Green
Write-Host ''
Write-Host 'Release contents:' -ForegroundColor Cyan
Get-ChildItem -LiteralPath $OutDir | ForEach-Object {
    Write-Host ("  {0,-44} {1,9:N0} bytes" -f $_.Name, $_.Length)
}

# ---------------------------------------------------------------------------
# Same-origin copy for the browser flasher.
#
# A browser cannot fetch a GitHub Release asset: browser_download_url 302s to
# release-assets.githubusercontent.com, and neither the redirect nor the final
# response sets Access-Control-Allow-Origin, so every download fails CORS.
# api.github.com *is* CORS-enabled, so listing the release worked and only the
# downloads failed — the page looked healthy until someone pressed Flash (#116).
#
# Publishing the same files under docs/ puts them on the origin that already
# serves the flasher. The Release stays the source of truth and keeps every
# asset; Pages carries only what the page actually downloads.
# ---------------------------------------------------------------------------
$PagesDir = Join-Path $RepoRoot "docs\firmware\$Version"
if (Test-Path $PagesDir) { Remove-Item -Recurse -Force $PagesDir }
New-Item -ItemType Directory -Force -Path $PagesDir | Out-Null

$pagesFiles = @()
foreach ($f in (Get-ChildItem -LiteralPath $OutDir -File | Sort-Object Name)) {
    # Only the images and the manifest; nothing else is fetched by the page.
    if ($f.Extension -notin @('.bin', '.json')) { continue }
    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $PagesDir $f.Name) -Force
    $pagesFiles += [ordered]@{ name = $f.Name; size = $f.Length }
}

$indexPath = Join-Path (Split-Path -Parent $PagesDir) 'index.json'
$index = [ordered]@{
    latest   = $Version
    releases = @(
        [ordered]@{
            version = $Version
            tag     = "v$Version"
            date    = (Get-Date -Format 'yyyy-MM-dd')
            files   = $pagesFiles
        }
    )
}
# No BOM: the flasher parses this with response.json().
[System.IO.File]::WriteAllText(
    $indexPath,
    ($index | ConvertTo-Json -Depth 8),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "Staged $($pagesFiles.Count) files for the browser flasher:" -ForegroundColor Cyan
Write-Host "  docs/firmware/$Version/  (+ docs/firmware/index.json)"
Write-Host '  Commit and push these with the release so the flasher can reach them.'

Write-Host ''
Write-Host 'Next step — create the GitHub Release (not run for you):' -ForegroundColor Cyan
Write-Host ''
# PowerShell does not glob-expand arguments to native executables and gh does not
# expand them itself, so "release/*" would reach gh literally. Expand it here.
Write-Host "  gh release create v$Version (Get-ChildItem release\* | ForEach-Object FullName) --title `"v$Version`" --generate-notes" -ForegroundColor White
Write-Host ''
Write-Host 'The browser flasher reads docs/firmware/index.json from this site, not'
Write-Host 'from the Release (a browser cannot fetch Release assets — no CORS headers).'
Write-Host 'Commit and push docs/firmware/ to make this version live in the flasher;'
Write-Host 'the GitHub Release is still the source of truth and carries every asset.'
