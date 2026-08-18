<#
.SYNOPSIS
    Asserts what install.ps1 decides, on a runner that is not Windows.

.DESCRIPTION
    No CI runner can register a Windows service, start a Scheduled Task, or
    enumerate a Windows host's adapters, so the half of install.ps1 that acts on
    a machine is verified by hand -- docs/service.md, Manual verification, is
    where those steps are. This file covers the other half: every decision the
    installer makes before it acts, driven directly.

    That split is deliberate and it is the same one internal/cli/fleetagent
    draws. install.ps1 keeps its decisions in functions that take what they
    judge and return an answer, dot-sourcing the file defines them without
    running the installer, and this asserts them. What it cannot see is a
    decision the installer stops consulting: the calls are in the run section
    below the dot-source guard, and only a Windows host walks that.

    No Pester. This needs an assertion and a count, both of which are cheaper
    than a module install on a job whose whole purpose is two linters.

    Run it anywhere pwsh is:

        pwsh -File ./install.tests.ps1
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'This is a test runner; its output is the report.')]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. "$PSScriptRoot/install.ps1"

$script:Failures = 0
$script:Checks = 0

function Assert-Equal {
    param([string] $What, $Expected, $Actual)

    $script:Checks++
    if ("$Expected" -ne "$Actual") {
        $script:Failures++
        Write-Host "FAIL  $What"
        Write-Host "        want: $Expected"
        Write-Host "        got:  $Actual"
    }
}

function Assert-Match {
    param([string] $What, [string] $Pattern, [string] $Actual)

    $script:Checks++
    if ($Actual -notmatch $Pattern) {
        $script:Failures++
        Write-Host "FAIL  $What"
        Write-Host "        want a match for: $Pattern"
        Write-Host "        got:              $Actual"
    }
}

# Where each address sits, which is the whole of what "no unsafe default" rests
# on. The boundaries are checked rather than one address per class: 100.64.0.0/10
# is the range every Tailscale node lives in, and an off-by-one at either end
# turns the answer this installer offers first into one the agent refuses.
$classCases = @(
    @{ Address = '0.0.0.0';         Want = 'wildcard' },
    @{ Address = '';                Want = 'wildcard' },
    @{ Address = '::';              Want = 'wildcard' },
    @{ Address = '127.0.0.1';       Want = 'loopback' },
    @{ Address = 'localhost';       Want = 'loopback' },
    @{ Address = '::1';             Want = 'loopback' },
    @{ Address = '10.0.0.4';        Want = 'private' },
    @{ Address = '172.15.0.1';      Want = 'public' },
    @{ Address = '172.16.0.1';      Want = 'private' },
    @{ Address = '172.31.255.254';  Want = 'private' },
    @{ Address = '172.32.0.1';      Want = 'public' },
    @{ Address = '192.168.1.20';    Want = 'private' },
    @{ Address = '100.63.255.255';  Want = 'public' },
    @{ Address = '100.64.0.1';      Want = 'cgnat' },
    @{ Address = '100.127.255.254'; Want = 'cgnat' },
    @{ Address = '100.128.0.1';     Want = 'public' },
    @{ Address = '169.254.10.4';    Want = 'linklocal' },
    @{ Address = '203.0.113.9';     Want = 'public' },
    @{ Address = 'fd7a:115c::1';    Want = 'private' },
    @{ Address = 'fe80::1';         Want = 'linklocal' },
    @{ Address = '2606:4700::1111'; Want = 'public' },
    @{ Address = 'build-box.internal'; Want = 'name' }
)
foreach ($case in $classCases) {
    Assert-Equal -What "$($case.Address) is $($case.Want)" -Expected $case.Want `
        -Actual (Get-FleetAddressClass -HostText $case.Address)
}

Assert-Equal -What 'host:port splits' -Expected '192.168.1.5' `
    -Actual (Split-FleetEndpoint -Endpoint '192.168.1.5:8722').Host
Assert-Equal -What 'host:port keeps its port' -Expected '8722' `
    -Actual (Split-FleetEndpoint -Endpoint '192.168.1.5:8722').Port
Assert-Equal -What 'a bracketed IPv6 host splits' -Expected 'fd7a::1' `
    -Actual (Split-FleetEndpoint -Endpoint '[fd7a::1]:8722').Host
Assert-Equal -What 'a bare host has no port' -Expected '' `
    -Actual (Split-FleetEndpoint -Endpoint '192.168.1.5').Port

# The refusal, which is failure 6 in #100: with mTLS off the daemon will not bind
# an address that is neither loopback nor private, and an installer that writes
# one anyway hands the operator a service that times out.
Assert-Match -What 'a wildcard is refused with mTLS off' -Pattern 'binds every interface' `
    -Actual (Get-FleetListenRefusal -ListenAddress '0.0.0.0:8722' -Mtls $false)
Assert-Match -What 'a public address is refused with mTLS off' -Pattern 'is a public address' `
    -Actual (Get-FleetListenRefusal -ListenAddress '203.0.113.9:8722' -Mtls $false)
Assert-Match -What 'a name is refused rather than resolved' -Pattern 'what DNS answers' `
    -Actual (Get-FleetListenRefusal -ListenAddress 'build-box.internal:8722' -Mtls $false)
Assert-Equal -What 'a tailnet address is not refused' -Expected '' `
    -Actual (Get-FleetListenRefusal -ListenAddress '100.83.4.17:8722' -Mtls $false)
Assert-Equal -What 'loopback is not refused' -Expected '' `
    -Actual (Get-FleetListenRefusal -ListenAddress '127.0.0.1:8722' -Mtls $false)
# With mTLS on the handshake is the boundary, and a wildcard bind is what
# `fleetctl enroll mint` prints. Refusing it here would refuse the command this
# product tells operators to paste.
Assert-Equal -What 'nothing is refused with mTLS on' -Expected '' `
    -Actual (Get-FleetListenRefusal -ListenAddress '0.0.0.0:8722' -Mtls $true)

# The menu. Tailscale first because it is almost always the right answer, and
# the two entries that widen who can reach this agent last.
$candidates = @(
    [pscustomobject]@{ Address = '203.0.113.9';  Interface = 'Ethernet';  Description = 'Intel(R) Ethernet Connection' },
    [pscustomobject]@{ Address = '127.0.0.1';    Interface = 'Loopback';  Description = 'Software Loopback Interface 1' },
    [pscustomobject]@{ Address = '192.168.1.20'; Interface = 'Wi-Fi';     Description = 'Wireless-AC 9560' },
    [pscustomobject]@{ Address = '100.83.4.17';  Interface = 'Tailscale'; Description = 'Tailscale Tunnel' }
)
$offered = Get-FleetAddressChoice -Candidate $candidates -Mtls $false
Assert-Equal -What 'the tailnet address is offered first' -Expected '100.83.4.17:8722' -Actual $offered[0].Address
Assert-Equal -What 'and is ranked ahead of everything else' -Expected 1 -Actual $offered[0].Rank
Assert-Match -What 'and is labelled as a tailnet address' -Pattern 'private to your tailnet' -Actual $offered[0].Label
Assert-Equal -What 'the private address comes next' -Expected '192.168.1.20:8722' -Actual $offered[1].Address
Assert-Equal -What 'loopback after that' -Expected '127.0.0.1:8722' -Actual $offered[2].Address
Assert-Equal -What 'the public address is offered last' -Expected '203.0.113.9:8722' -Actual $offered[3].Address
Assert-Match -What 'and is labelled PUBLIC' -Pattern 'PUBLIC' -Actual $offered[3].Label
Assert-Equal -What 'no wildcard is offered with mTLS off' -Expected 4 -Actual $offered.Count

# Ranked as Tailscale, not merely sorted first for being carrier space. A host
# with two CGNAT addresses is what tells those apart, and it is the shape that
# matters: the tailnet address is the one to offer.
$twoCarrier = @(
    [pscustomobject]@{ Address = '100.100.20.5'; Interface = 'CGNAT-uplink'; Description = 'Carrier NAT uplink' },
    [pscustomobject]@{ Address = '100.83.4.17';  Interface = 'Tailscale';    Description = 'Tailscale Tunnel' }
)
$carrier = Get-FleetAddressChoice -Candidate $twoCarrier -Mtls $false
Assert-Equal -What 'the tailnet address is offered before other carrier space' -Expected '100.83.4.17:8722' -Actual $carrier[0].Address
Assert-Equal -What 'and is ranked as Tailscale' -Expected 1 -Actual $carrier[0].Rank
Assert-Match -What 'the other is labelled carrier-grade NAT' -Pattern 'carrier-grade NAT' -Actual $carrier[1].Label
# The Windows adapter is called Tailscale; a renamed one still carries the
# description, which is why both are read.
$byDescription = Get-FleetAddressChoice -Mtls $false -Candidate @(
    [pscustomobject]@{ Address = '100.83.4.17'; Interface = 'Ethernet 3'; Description = 'Tailscale Tunnel' }
)
Assert-Equal -What 'a renamed Tailscale adapter is recognised by its description' -Expected 1 -Actual $byDescription[0].Rank

$offeredMtls = Get-FleetAddressChoice -Candidate $candidates -Mtls $true
Assert-Equal -What 'the wildcard is offered with mTLS on' -Expected '0.0.0.0:8722' -Actual $offeredMtls[4].Address
Assert-Equal -What 'and is offered last' -Expected 5 -Actual $offeredMtls.Count

# The default, which is the rule in #100 that has no exceptions: pressing return
# never widens who can reach this agent.
Assert-Equal -What 'the default is the tailnet address' -Expected 1 -Actual (Get-FleetDefaultChoice -Choice $offered)
Assert-Equal -What 'the wildcard is never the default' -Expected 1 -Actual (Get-FleetDefaultChoice -Choice $offeredMtls)
$publicOnly = Get-FleetAddressChoice -Candidate @(
    [pscustomobject]@{ Address = '203.0.113.9'; Interface = 'Ethernet'; Description = 'Intel(R) Ethernet Connection' }
) -Mtls $false
Assert-Equal -What 'a host with only a public address gets no default at all' -Expected 0 `
    -Actual (Get-FleetDefaultChoice -Choice $publicOnly)
$wildcardOnly = Get-FleetAddressChoice -Candidate @() -Mtls $true
Assert-Equal -What 'and neither does one offered only the wildcard' -Expected 0 `
    -Actual (Get-FleetDefaultChoice -Choice $wildcardOnly)

# A name the fleet cannot hold is one the printed `fleetctl add` line cannot be
# pasted with, which is the only reason this is checked here at all.
foreach ($case in @(
    @{ Name = 'build-box';   Want = $true },
    @{ Name = 'BUILD.box_2'; Want = $true },
    @{ Name = 'build box';   Want = $false },
    @{ Name = '';            Want = $false },
    @{ Name = 'sbx_abc';     Want = $false },
    @{ Name = ('a' * 129);   Want = $false },
    @{ Name = "build`tbox";  Want = $false },
    # Written as a code point rather than a character: these files carry no
    # BOM, so a literal one would be decoded as the host's ANSI code page.
    @{ Name = "build-bo$([char] 0x00DF)"; Want = $false }
)) {
    Assert-Equal -What "the fleet can hold '$($case.Name)': $($case.Want)" -Expected $case.Want `
        -Actual (Test-FleetSandboxName -SandboxName $case.Name)
}

# Item 4 in #100: a definition marked for deletion is a wait-and-retry.
Assert-Equal -What 'marked for deletion is transient' -Expected $true `
    -Actual (Test-FleetTransientRegistration -Output 'The specified service has been marked for deletion.')
Assert-Equal -What 'so is the "already exists" it wears' -Expected $true `
    -Actual (Test-FleetTransientRegistration -Output 'install service: service fleet-agent already exists')
Assert-Equal -What 'access denied is not transient' -Expected $false `
    -Actual (Test-FleetTransientRegistration -Output 'Access is denied.')
Assert-Equal -What 'and neither is nothing at all' -Expected $false `
    -Actual (Test-FleetTransientRegistration -Output '')

# Item 8: -Listen is the socket bound here and -Address is what the control
# plane dials, and a wildcard is not an address anybody dials.
Assert-Equal -What 'an explicit -Address wins' -Expected 'build-box.internal:8722' `
    -Actual (Get-FleetWorkstationAddress -ListenAddress '0.0.0.0:8722' -Advertised @('build-box.internal:8722') -Choice $offered)
Assert-Equal -What 'a concrete listen address is what to dial' -Expected '100.83.4.17:8722' `
    -Actual (Get-FleetWorkstationAddress -ListenAddress '100.83.4.17:8722' -Advertised @() -Choice $offered)
Assert-Equal -What 'a wildcard becomes the best address this host has' -Expected '100.83.4.17:8722' `
    -Actual (Get-FleetWorkstationAddress -ListenAddress '0.0.0.0:8722' -Advertised @() -Choice $offered)

# Item 9: nothing on the agent side said the fleet member still had to be added.
$next = (Get-FleetNextStep -SandboxName 'build-box' -WorkstationAddress '100.83.4.17:8722' -Mtls $false) -join "`n"
Assert-Match -What 'the no-mTLS posture prints the command to paste' `
    -Pattern 'fleetctl add build-box --address 100\.83\.4\.17:8722 --insecure' -Actual $next
$nextMtls = (Get-FleetNextStep -SandboxName 'build-box' -WorkstationAddress '100.83.4.17:8722' -Mtls $true) -join "`n"
Assert-Match -What 'the mTLS posture says enrollment already registered it' -Pattern 'fleetctl list' -Actual $nextMtls
Assert-Equal -What 'and does not tell an enrolled host to add itself as insecure' -Expected $false `
    -Actual ($nextMtls -match '--insecure')

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$($script:Failures) of $($script:Checks) checks failed"
    exit 1
}
Write-Host "$($script:Checks) checks passed"
