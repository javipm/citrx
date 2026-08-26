param(
  [Parameter(Mandatory = $true)]
  [string]$NodeVersion
)

$ErrorActionPreference = "Stop"
$Archive = "node-v$NodeVersion-win-x64.zip"
$DownloadBase = "https://nodejs.org/dist/v$NodeVersion"
$InstallRoot = Join-Path $env:RUNNER_TEMP "citrx-node-$NodeVersion"
$ArchivePath = Join-Path $InstallRoot $Archive
$ChecksumsPath = Join-Path $InstallRoot "SHASUMS256.txt"
$NodeRoot = Join-Path $InstallRoot "node-v$NodeVersion-win-x64"
$NpmPrefix = Join-Path $InstallRoot "npm-global"

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri "$DownloadBase/$Archive" -OutFile $ArchivePath
Invoke-WebRequest -Uri "$DownloadBase/SHASUMS256.txt" -OutFile $ChecksumsPath

$EscapedArchive = [Regex]::Escape($Archive)
$ChecksumLine = Get-Content $ChecksumsPath |
  Where-Object { $_ -match "\s+$EscapedArchive$" } |
  Select-Object -First 1

if (-not $ChecksumLine) {
  throw "Missing checksum for $Archive"
}

$ExpectedChecksum = ($ChecksumLine -split "\s+")[0].ToLowerInvariant()
$ActualChecksum = (Get-FileHash -Algorithm SHA256 -LiteralPath $ArchivePath).Hash.ToLowerInvariant()
if ($ActualChecksum -ne $ExpectedChecksum) {
  throw "Checksum mismatch for $Archive"
}

Expand-Archive -LiteralPath $ArchivePath -DestinationPath $InstallRoot -Force
$env:PATH = "$NodeRoot;$NpmPrefix;$env:PATH"

node --version
npm.cmd --version
npm.cmd install --global --prefix $NpmPrefix pnpm@11.1.0
pnpm.cmd --version
