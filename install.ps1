<#
.SYNOPSIS
    Installs sandboxd-agent on a Windows host.

.DESCRIPTION
    Downloads the release binary for this platform, verifies its SHA-256
    against the release checksum file, installs it, and optionally enrolls the
    host and registers a Windows service.

    Piping a script from the network into a shell is trust-on-first-use no
    matter how careful the script is. This one at least refuses to install an
    artifact whose checksum does not match the one published alongside it, and
    it pins the control-plane CA when you give it a fingerprint.

.EXAMPLE
    irm https://raw.githubusercontent.com/axelmierczuk/sandboxd-mcp/main/install.ps1 | iex

.EXAMPLE
    $s = irm https://raw.githubusercontent.com/axelmierczuk/sandboxd-mcp/main/install.ps1
    & ([scriptblock]::Create($s)) -Token abc123 -Control control.local:9443 -Root C:\workspace
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Installer progress must be visible when this script is piped into iex; the information stream is not shown by default there.')]
param(
    # Enrollment token from `sandboxctl enroll mint`. When set, the host
    # enrolls after installation.
    [string] $Token,

    # Control-plane enrollment endpoint, host:port.
    [string] $Control,

    # SHA-256 fingerprint of the control-plane CA to pin. Strongly recommended.
    [string] $CaFingerprint,

    # Address the agent serves gRPC on.
    [string] $Listen = '0.0.0.0:8722',

    # Sandbox name to request. Defaults to the computer name.
    [string] $Name,

    # Filesystem roots the agent may access. Without any, no path jail applies.
    [string[]] $Root = @(),

    # Release to install.
    [string] $Version = 'latest',

    # Install prefix.
    [string] $InstallDir,

    # Register a Windows service. Defaults to true when running elevated.
    [ValidateSet('yes', 'no', 'auto')]
    [string] $Service = 'auto',

    # Skip checksum verification. Do not use this.
    [switch] $SkipChecksum
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo    = 'axelmierczuk/sandboxd-mcp'
$BaseUrl = "https://github.com/$Repo/releases"
$ApiUrl  = "https://api.github.com/repos/$Repo/releases"

function Write-Step { param([string] $Message) Write-Host "  $Message" }
function Write-Warn { param([string] $Message) Write-Warning $Message }

function Test-Elevated {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Architecture {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

function Resolve-ReleaseVersion {
    param([string] $Requested)
    if ($Requested -ne 'latest') { return $Requested }
    $release = Invoke-RestMethod -Uri "$ApiUrl/latest" -UseBasicParsing
    if (-not $release.tag_name) {
        throw 'Could not resolve the latest release tag; pass -Version explicitly.'
    }
    return $release.tag_name
}

$arch      = Resolve-Architecture
$resolved  = Resolve-ReleaseVersion -Requested $Version
$elevated  = Test-Elevated

if (-not $InstallDir) {
    $InstallDir = if ($elevated) {
        Join-Path $env:ProgramFiles 'sandboxd'
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\sandboxd'
    }
}

if ($Service -eq 'auto') {
    $Service = if ($elevated) { 'yes' } else { 'no' }
}
if ($Service -eq 'yes' -and -not $elevated) {
    throw 'Registering a Windows service requires an elevated PowerShell session.'
}

$archive      = "sandboxd-agent_windows_$arch.zip"
$archiveUrl   = "$BaseUrl/download/$resolved/$archive"
$checksumUrl  = "$BaseUrl/download/$resolved/checksums.txt"

Write-Step "sandboxd-agent $resolved for windows/$arch"

$work = Join-Path ([IO.Path]::GetTempPath()) ("sandboxd-" + [Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    $archivePath = Join-Path $work $archive

    Write-Step "downloading $archive"
    Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing

    if ($SkipChecksum) {
        Write-Warn 'Checksum verification skipped at your request.'
    } else {
        Write-Step 'verifying checksum'
        $checksumPath = Join-Path $work 'checksums.txt'
        Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumPath -UseBasicParsing

        $line = Select-String -Path $checksumPath -Pattern ([regex]::Escape($archive)) |
                Select-Object -First 1
        if (-not $line) { throw "No checksum published for $archive." }

        $expected = ($line.Line -split '\s+')[0].ToLowerInvariant()
        $actual   = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($expected -ne $actual) {
            throw @"
Checksum mismatch for $archive
  expected $expected
  actual   $actual
This means the download was corrupted or tampered with. Not installing.
"@
        }
        Write-Step 'checksum ok'
    }

    Write-Step 'extracting'
    Expand-Archive -Path $archivePath -DestinationPath $work -Force

    $binary = Join-Path $work 'sandboxd-agent.exe'
    if (-not (Test-Path $binary)) { throw 'Archive did not contain sandboxd-agent.exe.' }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $target = Join-Path $InstallDir 'sandboxd-agent.exe'
    Copy-Item -Path $binary -Destination $target -Force

    Write-Step "installed $target"

    # Put the install directory on PATH for the appropriate scope, so the
    # operator can run `sandboxd-agent` without qualifying it.
    $scope    = if ($elevated) { 'Machine' } else { 'User' }
    $current  = [Environment]::GetEnvironmentVariable('Path', $scope)
    if ($current -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$current;$InstallDir", $scope)
        Write-Step "added $InstallDir to the $scope PATH (restart your shell to pick it up)"
    }

    if ($Token) {
        if (-not $Control) { throw '-Token requires -Control.' }

        $enrollArgs = @('enroll', '--token', $Token, '--control', $Control, '--listen', $Listen)
        if ($Name)          { $enrollArgs += @('--name', $Name) }
        if ($CaFingerprint) { $enrollArgs += @('--ca-fingerprint', $CaFingerprint) }
        foreach ($r in $Root) { $enrollArgs += @('--root', $r) }

        if (-not $CaFingerprint) {
            Write-Warn 'Enrolling without -CaFingerprint: the control plane certificate is not pinned.'
        }
        if ($Root.Count -eq 0) {
            Write-Warn 'No -Root given: the agent will start without a filesystem jail.'
        }

        Write-Step "enrolling with $Control"
        & $target @enrollArgs
        if ($LASTEXITCODE -ne 0) { throw "Enrollment failed with exit code $LASTEXITCODE." }

        if ($Service -eq 'yes') {
            Write-Step 'registering Windows service'
            & $target service install
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "Service registration failed; run 'sandboxd-agent service install' manually."
            } else {
                & $target service start
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "Service did not start; check 'sandboxd-agent service status'."
                }
            }
        }

        Write-Step 'done. This host should now appear in sandbox_list.'
    } else {
        Write-Host @"

  Installed, but not enrolled. To join a fleet:

    $target enroll ``
      --token <enrollment-token> ``
      --control <control-host:9443> ``
      --root C:\path\to\workspace

  Mint a token on the control host with: sandboxctl enroll mint
"@
    }
} finally {
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
