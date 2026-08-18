<#
.SYNOPSIS
    Installs fleet-agent on a Windows host.

.DESCRIPTION
    Downloads the release binary for this platform, verifies its SHA-256
    against the release checksum file, installs it where the account the agent
    runs as can read it, writes a config, registers the agent to start at
    logon, starts it, and checks that it came up before saying so.

    It asks when it has a console and has not been told. Every parameter below
    still works exactly as it did, and that is the path CI and provisioning
    scripts take: interactive is what happens when a console is present *and* a
    required answer is missing.

    No prompt has an unsafe default, and the listen address is why that rule
    exists. 0.0.0.0 is the obvious thing to type, and with mTLS off it is
    exactly what the agent's own guard refuses -- which arrives through the
    service control manager as "the service did not respond in a timely
    fashion", several steps removed from the answer that caused it. So the
    addresses this host actually has are enumerated and offered, labelled by
    what can reach them, with a Tailscale address first.

    Registration defaults to a logon-triggered Scheduled Task running as the
    account that ran this script, in that account's own session. A Windows
    service would run in session 0, which has no operator profile and therefore
    no nvm, rustup, pyenv, cargo, scoop or npm globals: see docs/service.md.
    Use `fleet-agent service install --mechanism service --user <account>` for
    a headless box.

    Piping a script from the network into a shell is trust-on-first-use no
    matter how careful the script is. This one at least refuses to install an
    artifact whose checksum does not match the one published alongside it, and
    it always pins the control-plane CA: enrollment will not run without a
    fingerprint.

.EXAMPLE
    irm https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.ps1 | iex

.EXAMPLE
    $s = irm https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.ps1
    & ([scriptblock]::Create($s)) -Token abc123 -Control control.local:9443 `
        -CaFingerprint 9f86d0...  -Root C:\workspace
#>
[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Installer progress must be visible when this script is piped into iex; the information stream is not shown by default there.')]
param(
    # Enrollment token from `fleetctl enroll mint`. Selects mTLS: the host
    # enrolls after installation, and -Control and -CaFingerprint are required.
    [string] $Token,

    # Control-plane enrollment endpoint, host:port.
    [string] $Control,

    # SHA-256 fingerprint of the control-plane CA to pin, from
    # `fleetctl ca fingerprint`. Required with -Token: enrollment refuses to
    # run unpinned.
    [string] $CaFingerprint,

    # Configure an agent that authenticates nobody, for a network that
    # authenticates its own peers. -Listen becomes required: there is no safe
    # default for it.
    [switch] $NoMtls,

    # Address the agent serves gRPC on. With -Token it defaults to
    # 0.0.0.0:8722; with -NoMtls it has no default, and a public or wildcard
    # address is refused.
    [string] $Listen,

    # Address the control plane dials this host by, which is not the same thing
    # as -Listen. It becomes a subject alternative name on the issued
    # certificate. Defaults to -Listen when that names a concrete address.
    [string[]] $Address = @(),

    # Sandbox name. With -Token, only for a token that reserved none; the
    # control plane refuses a name other than the one its token authorizes.
    [string] $Name,

    # Filesystem roots the agent may access. Enforced only when exec.enabled is
    # false in the config: a caller that can run commands reaches any path
    # without going through FileService.
    [string[]] $Root = @(),

    # Release to install.
    [string] $Version = 'latest',

    # Where the release assets are, for a mirror of the GitHub release layout.
    # The checksum check is unchanged: the mirror publishes checksums.txt too,
    # and a mismatch still refuses to install.
    [string] $BaseUrl,

    # Install prefix.
    [string] $InstallDir,

    # Directory to write agent.yaml into. Defaults to %ProgramData%\fleet when
    # elevated, and to the per-user enrollment directory otherwise.
    [string] $ConfigDir,

    # Register the agent to start at logon. Defaults to true when running
    # elevated. See docs/service.md for the two mechanisms and which one this
    # picks.
    [ValidateSet('yes', 'no', 'auto')]
    [string] $Service = 'auto',

    # Never ask, even with a console. A missing answer is then an error naming
    # the parameter that supplies it.
    [switch] $NonInteractive,

    # Resolve everything, print the plan, change nothing.
    [switch] $DryRun,

    # Skip checksum verification. Do not use this.
    [switch] $SkipChecksum
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo      = 'axelmierczuk/fleet-mcp'
$ApiUrl    = "https://api.github.com/repos/$Repo/releases"
if (-not $BaseUrl) { $BaseUrl = "https://github.com/$Repo/releases" }
$ScriptUrl = "https://raw.githubusercontent.com/$Repo/main/install.ps1"

# The port an address is offered on when the operator picks one from the menu.
# It is internal/agent's DefaultListen port and what the MCP server's registry
# records by default.
$DefaultPort = 8722

# What the scripted mTLS path listens on when no -Listen is given. It stays what
# it has always been: `fleetctl enroll mint` prints this exact invocation, and a
# wildcard bind is an ordinary deployment for an agent that authenticates every
# caller by certificate. The guard that refuses it applies only with mTLS off,
# and that posture has no default at all.
$MtlsDefaultListen = '0.0.0.0:8722'

function Write-Step { param([string] $Message) Write-Host "  $Message" }
function Write-Warn { param([string] $Message) Write-Warning $Message }

# ---------------------------------------------------------------- decisions --
#
# Everything from here to the marker below decides something without touching
# the machine, so that what a Windows host will do can be asserted on any
# runner. install.tests.ps1 drives these directly; no CI runner can register a
# service, and dot-sourcing this file defines them without running the
# installer.

function Split-FleetEndpoint {
    <#
    .SYNOPSIS
        Splits host:port, tolerating a bracketed IPv6 host and a bare host.
    #>
    param([string] $Endpoint)

    $text = if ($null -eq $Endpoint) { '' } else { $Endpoint.Trim() }
    if ($text -match '^\[(?<h>.*)\]:(?<p>[^:]*)$') {
        return [pscustomobject]@{ Host = $Matches['h']; Port = $Matches['p'] }
    }
    $colon = $text.LastIndexOf(':')
    if ($colon -ge 0 -and $text.IndexOf(':') -eq $colon) {
        return [pscustomobject]@{ Host = $text.Substring(0, $colon); Port = $text.Substring($colon + 1) }
    }
    return [pscustomobject]@{ Host = $text; Port = '' }
}

function Get-FleetAddressClass {
    <#
    .SYNOPSIS
        Names what can reach an address, in internal/agent's terms.
    .DESCRIPTION
        The daemon's CheckListenPosture is the authority. This exists so the
        same question can be answered while the operator is still being asked
        it, rather than after a service fails to start.

        A name is classified as a name rather than resolved, for the reason the
        daemon gives: resolving would make the answer depend on what DNS said
        at this instant.
    #>
    param([string] $HostText)

    $text = if ($null -eq $HostText) { '' } else { $HostText.Trim().Trim('[', ']') }
    if ($text -eq '' -or $text -eq '0.0.0.0' -or $text -eq '::') { return 'wildcard' }
    if ($text -eq 'localhost') { return 'loopback' }

    $ip = [Net.IPAddress]::Loopback
    if (-not [Net.IPAddress]::TryParse($text, [ref] $ip)) { return 'name' }
    if ([Net.IPAddress]::IsLoopback($ip)) { return 'loopback' }

    $bytes = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -eq 0) { return 'wildcard' }
        if ($bytes[0] -eq 10) { return 'private' }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return 'private' }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return 'private' }
        # 100.64.0.0/10, RFC 6598. Not private by any library's reckoning -- it
        # is carrier space -- and it is where every Tailscale node lives, which
        # is the deployment the no-mTLS posture exists for.
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return 'cgnat' }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'linklocal' }
        return 'public'
    }
    if (($bytes[0] -band 0xfe) -eq 0xfc) { return 'private' }
    if ($bytes[0] -eq 0xfe -and ($bytes[1] -band 0xc0) -eq 0x80) { return 'linklocal' }
    return 'public'
}

function Get-FleetListenRefusal {
    <#
    .SYNOPSIS
        Says why the daemon would refuse to bind this address, or nothing.
    .DESCRIPTION
        With mTLS on it refuses nothing: the handshake is the boundary and a
        public address is a legitimate deployment. With mTLS off only an address
        whose reachability is already bounded is permitted.
    #>
    param([string] $ListenAddress, [bool] $Mtls)

    if ($Mtls) { return $null }
    $addressHost = (Split-FleetEndpoint -Endpoint $ListenAddress).Host
    switch (Get-FleetAddressClass -HostText $addressHost) {
        'wildcard' { return "$ListenAddress binds every interface on this host, including any public one" }
        'public'   { return "$ListenAddress is a public address" }
        'name'     { return "$ListenAddress names a host this agent cannot judge: it is not an IP address, and resolving it would make the check depend on what DNS answers" }
        default    { return $null }
    }
}

function Get-FleetListenRemedy {
    <#
    .SYNOPSIS
        The three ways out of the refusal above, in the order to prefer them.
    #>
    return @(
        'With mTLS off this agent authenticates nobody: anyone who can reach this port',
        'can run commands on this host as the account it runs as. Either:',
        '  - enroll this host, so callers are authenticated by certificate: re-run',
        '    with -Token, -Control and -CaFingerprint; or',
        '  - listen on a loopback or private address -- a tailnet or VPC address is',
        '    what this posture is for.'
    )
}

function Get-FleetAddressChoice {
    <#
    .SYNOPSIS
        Orders the addresses this host has, best answer first, and labels each
        by what can reach it.
    .DESCRIPTION
        Candidates are objects with Address, Interface and Description, so that
        the ordering can be asserted against a host that does not exist. Rank 1
        is a Tailscale address: it is private, on a network that already
        authenticates its peers, and it is almost always the right answer.
        Ranks 6 and 7 -- a public address, and every interface -- are the two
        that must never be reached by pressing return, which is what
        Get-FleetDefaultChoice reads the rank for.
    #>
    param([object[]] $Candidate, [bool] $Mtls)

    $choices = @()
    foreach ($item in $Candidate) {
        $class = Get-FleetAddressClass -HostText $item.Address
        $where = $item.Interface
        $tailscale = ($item.Interface -match 'tailscale' -or $item.Description -match 'Tailscale')
        switch ($class) {
            'cgnat' {
                if ($tailscale) {
                    $choices += [pscustomobject]@{ Rank = 1; Address = "$($item.Address):$DefaultPort"; Label = "$where, Tailscale - private to your tailnet" }
                } else {
                    $choices += [pscustomobject]@{ Rank = 2; Address = "$($item.Address):$DefaultPort"; Label = "$where, carrier-grade NAT (100.64.0.0/10) - a tailnet address" }
                }
            }
            'private'   { $choices += [pscustomobject]@{ Rank = 3; Address = "$($item.Address):$DefaultPort"; Label = "$where, private" } }
            'loopback'  { $choices += [pscustomobject]@{ Rank = 4; Address = "$($item.Address):$DefaultPort"; Label = "$where, loopback - reachable only from this host" } }
            'linklocal' { $choices += [pscustomobject]@{ Rank = 5; Address = "$($item.Address):$DefaultPort"; Label = "$where, link-local" } }
            default     { $choices += [pscustomobject]@{ Rank = 6; Address = "$($item.Address):$DefaultPort"; Label = "$where, PUBLIC - reachable from anywhere that routes to it" } }
        }
    }
    # Offered only with mTLS on, where the handshake is the boundary and binding
    # every interface is an ordinary deployment. With mTLS off it is the exact
    # answer this whole question exists to stop being typed, so it is not on the
    # menu -- and Get-FleetListenRefusal refuses it if it is typed anyway.
    if ($Mtls) {
        $choices += [pscustomobject]@{ Rank = 7; Address = $MtlsDefaultListen; Label = 'every interface - fine with mTLS, where the handshake is the boundary' }
    }
    return @($choices | Sort-Object -Property Rank)
}

function Get-FleetDefaultChoice {
    <#
    .SYNOPSIS
        The 1-based index of the first offer that may be a default, or 0.
    .DESCRIPTION
        An answer that widens who can reach this agent is never the one an
        operator gets by pressing return. A host whose only address is public
        therefore gets no default at all.
    #>
    param([object[]] $Choice)

    for ($i = 0; $i -lt $Choice.Count; $i++) {
        if ($Choice[$i].Rank -lt 6) { return $i + 1 }
    }
    return 0
}

function Test-FleetSandboxName {
    <#
    .SYNOPSIS
        Reports whether the fleet can hold this name.
    .DESCRIPTION
        registry.CheckName is the authority and applies the same rule: printable
        ASCII with no spaces, at most 128 bytes, and nothing starting with the
        handle prefix. It is worth applying here because this script *prints a
        command* built from the name -- `fleetctl add build box --address ...` is
        not a command, and an operator finds that out by pasting it.
    #>
    param([string] $SandboxName)

    if ([string]::IsNullOrEmpty($SandboxName)) { return $false }
    if ($SandboxName.StartsWith('sbx_')) { return $false }
    if ($SandboxName.Length -gt 128) { return $false }
    foreach ($character in $SandboxName.ToCharArray()) {
        if ([int] $character -le 32 -or [int] $character -gt 126) { return $false }
    }
    return $true
}

function Get-FleetNameRule {
    return @(
        'A sandbox name is printable ASCII with no spaces, at most 128 bytes, and does',
        'not start with sbx_. It is typed on a command line and printed in a table --',
        'including in the `fleetctl add` line this prints at the end.'
    )
}

function Test-FleetTransientRegistration {
    <#
    .SYNOPSIS
        Reports whether a failed registration is one that clears itself.
    .DESCRIPTION
        DeleteService only *marks* a running Windows service for deletion: the
        entry survives in the SCM database until the last handle to it closes,
        and the CreateService that follows fails. It is the state an
        uninstall-then-install lands in, it clears in seconds, and reported raw
        it reads like a broken machine -- item 4 in #100.

        "already exists" is the same condition wearing the other name: with the
        definition still marked, OpenService keeps finding it, and that is what
        the service library reports. `service install` replaces an existing
        definition itself, so an "already exists" that reaches this script is
        one it could not remove.
    #>
    param([string] $Output)

    if ([string]::IsNullOrEmpty($Output)) { return $false }
    return ($Output -match 'marked for deletion') -or ($Output -match 'already exists')
}

function Get-FleetWorkstationAddress {
    <#
    .SYNOPSIS
        What a workstation dials this host by, which is not always -Listen.
    .DESCRIPTION
        A wildcard names no address at all, so the best address this host has is
        offered instead; loopback names one only this host can reach.
    #>
    param([string] $ListenAddress, [string[]] $Advertised, [object[]] $Choice)

    if ($Advertised -and $Advertised.Count -gt 0) { return $Advertised[0] }
    $listenHost = (Split-FleetEndpoint -Endpoint $ListenAddress).Host
    if ((Get-FleetAddressClass -HostText $listenHost) -ne 'wildcard') { return $ListenAddress }
    $usable = @($Choice | Where-Object { $_.Rank -lt 6 })
    if ($usable.Count -gt 0) { return $usable[0].Address }
    return $ListenAddress
}

function Get-FleetNextStep {
    <#
    .SYNOPSIS
        The command to finish the job, on the workstation rather than here.
    .DESCRIPTION
        Item 9 in #100: nothing on the agent side said the fleet member still
        had to be added, or how. Enrollment registers the sandbox as a side
        effect of the handshake, so the mTLS posture has nothing left to do and
        says so; the no-mTLS posture has no other way for the entry to exist.
    #>
    param([string] $SandboxName, [string] $WorkstationAddress, [bool] $Mtls)

    $name = if ([string]::IsNullOrWhiteSpace($SandboxName)) { '<name>' } else { $SandboxName }
    if ($Mtls) {
        return @(
            'Enrollment registered this host, so it is already in your fleet:',
            '',
            '    fleetctl list',
            '',
            'If it is not there -- an enrollment that reached a control plane holding a',
            'different registry, most often -- add it by hand:',
            '',
            "    fleetctl add $name --address $WorkstationAddress"
        )
    }
    return @(
        'Nothing on this host can register it. Finish on your workstation:',
        '',
        "    fleetctl add $name --address $WorkstationAddress --insecure",
        '',
        'That records the name, the address and the posture in the fleet registry,',
        'which is what the MCP server reads. --insecure is not a shortcut: it says',
        'this host authenticates nobody, and `add` refuses the entry if the host',
        'contradicts it.'
    )
}

# ------------------------------------------------------------------- host ----
#
# From here on everything touches the machine: it asks the console, queries the
# adapters, writes files, and runs the agent.

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

function Get-FleetHostAddress {
    <#
    .SYNOPSIS
        Every IPv4 address on an interface that is up, with the interface's own
        name and description.
    .DESCRIPTION
        Read through .NET rather than Get-NetIPAddress so that the adapter's
        description comes with it: the Tailscale adapter is called "Tailscale"
        on Windows, and that is what tells its address apart from any other
        tunnel's.
    #>
    $found = @()
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up) { continue }
        foreach ($unicast in $nic.GetIPProperties().UnicastAddresses) {
            if ($unicast.Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            $found += [pscustomobject]@{
                Address     = $unicast.Address.IPAddressToString
                Interface   = $nic.Name
                Description = $nic.Description
            }
        }
    }
    return $found
}

function Test-FleetConsole {
    <#
    .SYNOPSIS
        Reports whether there is somebody to ask.
    .DESCRIPTION
        Redirected input is a script, a CI step or a scheduled run, and a
        question put to one of those is a question nobody will ever answer --
        which is #73's shape and the reason this is checked rather than assumed.
        `irm | iex` does not redirect input: the script arrives over the wire,
        not on stdin, so an operator running the documented one-liner is asked.
        not on stdin, so an operator running the documented one-liner is asked.

        Suppressed is -NonInteractive, passed in rather than read from the
        enclosing scope so that what this decides is a function of its
        arguments.
    #>
    param([bool] $Suppressed)

    if ($Suppressed) { return $false }
    try { return -not [Console]::IsInputRedirected } catch { return $false }
}

function Test-FleetListener {
    <#
    .SYNOPSIS
        Reports whether anything accepts a connection at the address the config
        names.
    .DESCRIPTION
        Deliberately not a claim about gRPC. The release archive carries the
        agent alone, so there is no fleet client on this host to speak the
        protocol with; what can be established here is that the manager reports
        a running daemon and that its socket answers. `fleetctl add` on the
        workstation is what proves it serves, and it is the line this installer
        ends by printing.

        A wildcard binds every interface, so loopback is what gets dialled for
        it: connecting to 0.0.0.0 is not a thing a client does.
    #>
    param([string] $ListenAddress)

    $endpoint = Split-FleetEndpoint -Endpoint $ListenAddress
    $probeHost = $endpoint.Host
    if ((Get-FleetAddressClass -HostText $probeHost) -eq 'wildcard') { $probeHost = '127.0.0.1' }

    for ($i = 0; $i -lt 20; $i++) {
        $client = New-Object Net.Sockets.TcpClient
        try {
            if ($client.ConnectAsync($probeHost, [int] $endpoint.Port).Wait(2000)) { return $true }
        } catch {
            # A refused connection is the ordinary answer while a daemon is
            # still binding, and not a reason to stop asking. Kept out of the
            # operator's way and available with -Verbose, because the thing
            # worth reporting is the whole probe timing out, which the caller
            # reports with the address in it.
            Write-Verbose "connecting to ${probeHost}: $_"
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Read-FleetAnswer {
    <#
    .SYNOPSIS
        Puts one question and returns the answer.
    .DESCRIPTION
        NeedsFlag names what would have answered it without a console, so the
        refusal an unattended run gets is the command line it was missing.

        An empty answer takes the default where there is one, and there is
        deliberately none for the questions that decide who can reach this
        agent. A console that has gone away answers empty forever, so a run of
        them is treated as the end of input rather than spun on: an installer
        that hangs is worse than one that stops and says what to pass.
    #>
    param([string] $Question, [string] $Default, [string] $NeedsFlag)

    $empties = 0
    while ($true) {
        $prompt = if ($Default) { "$Question [$Default]" } else { $Question }
        $reply = $null
        try { $reply = Read-Host -Prompt $prompt } catch { $reply = $null }
        if ($null -eq $reply) {
            throw "No answer: the console gave none. Pass $NeedsFlag to answer this without one."
        }
        $reply = $reply.Trim()
        if ($reply) { return $reply }
        if ($Default) { return $Default }
        $empties++
        if ($empties -ge 5) {
            throw "No answer: this question has no default and five empty replies came back. Pass $NeedsFlag."
        }
        Write-Host '  this one has no default; an answer is needed.'
    }
}

function Read-FleetPosture {
    Write-Host ''
    Write-Host 'How should callers of this agent be authenticated?'
    Write-Host ''
    Write-Host '  1) mTLS. This host enrolls against your fleet CA and both ends present a'
    Write-Host '     certificate. Needs an enrollment token, the control address and the CA'
    Write-Host '     fingerprint -- `fleetctl enroll mint` prints all three.'
    Write-Host '  2) None. The agent authenticates nobody, and whatever keeps people out is'
    Write-Host '     the network: a tailnet, a WireGuard mesh, a VPC with tight security'
    Write-Host '     groups. Anyone who can reach its port can run commands on this host.'
    Write-Host ''
    while ($true) {
        $answer = Read-FleetAnswer -Question 'Authentication [1 or 2]' -Default '' -NeedsFlag '-Token or -NoMtls'
        switch ($answer) {
            '1'    { return $true }
            'mtls' { return $true }
            '2'    { return $false }
            'none' { return $false }
            default { Write-Host '  answer 1 or 2.' }
        }
    }
}

function Read-FleetListen {
    <#
    .SYNOPSIS
        Offers the addresses this host has and returns the one chosen.
    #>
    param([bool] $Mtls)

    $choices = Get-FleetAddressChoice -Candidate (Get-FleetHostAddress) -Mtls $Mtls

    Write-Host ''
    Write-Host 'Which address should the agent serve on?'
    Write-Host ''
    Write-Host 'This is the socket it binds. It is not necessarily how your workstation'
    Write-Host 'reaches this host -- that is asked separately, and getting the two confused'
    Write-Host 'produces an agent nobody can dial.'
    Write-Host ''
    for ($i = 0; $i -lt $choices.Count; $i++) {
        Write-Host ("  {0}) {1,-22} {2}" -f ($i + 1), $choices[$i].Address, $choices[$i].Label)
    }
    Write-Host '  0) something else'
    Write-Host ''

    $defaultIndex = Get-FleetDefaultChoice -Choice $choices
    $default = if ($defaultIndex -gt 0) { "$defaultIndex" } else { '' }

    while ($true) {
        $pick = Read-FleetAnswer -Question 'Address' -Default $default -NeedsFlag '-Listen'
        $candidate = ''
        if ($pick -eq '0') {
            $candidate = Read-FleetAnswer -Question 'Address as host:port' -Default '' -NeedsFlag '-Listen'
        } elseif ($pick -match '^[0-9]+$' -and [int] $pick -le $choices.Count) {
            $candidate = $choices[[int] $pick - 1].Address
        } else {
            Write-Host '  answer with one of the numbers above.'
            continue
        }
        if (-not (Split-FleetEndpoint -Endpoint $candidate).Port) {
            $candidate = "${candidate}:$DefaultPort"
        }
        $refusal = Get-FleetListenRefusal -ListenAddress $candidate -Mtls $Mtls
        if (-not $refusal) { return $candidate }
        Write-Host ''
        Write-Host "  refused: $refusal."
        foreach ($line in Get-FleetListenRemedy) { Write-Host $line }
        Write-Host ''
    }
}

# ------------------------------------------------------------------- run -----
#
# Dot-sourcing this file defines everything above and stops here, which is how
# install.tests.ps1 asserts a Windows decision on a runner that is not Windows.
# Every other way of invoking it -- `pwsh -File`, `irm | iex`, and the
# `& ([scriptblock]::Create($s))` form this file's examples print -- runs the
# installer.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($Token -and $NoMtls) {
    throw @'
-Token and -NoMtls ask for opposite postures: -Token enrolls this host against a
CA so both ends present a certificate, and -NoMtls configures an agent that
authenticates nobody. Pass one.
'@
}

$arch     = Resolve-Architecture
$elevated = Test-Elevated
$console  = Test-FleetConsole -Suppressed $NonInteractive.IsPresent

# The posture, and whether there is anything to configure at all. Nothing on the
# command line and no console is `irm | iex` with no arguments -- the "put the
# agent on the host" step in the README -- which has always installed the binary
# and stopped. It still does: an install that started guessing at a posture
# would be guessing about who may run commands on this machine.
$binaryOnly = $false
$mtls = $false
if ($Token) {
    $mtls = $true
} elseif ($NoMtls) {
    $mtls = $false
} elseif ($console) {
    $mtls = Read-FleetPosture
} else {
    $binaryOnly = $true
}

if (-not $binaryOnly -and $mtls) {
    if (-not $Token) {
        if (-not $console) { throw '-Token is required to enroll.' }
        $Token = Read-FleetAnswer -Question 'Enrollment token' -Default '' -NeedsFlag '-Token'
    }
    if (-not $Control) {
        if (-not $console) { throw '-Token requires -Control <host:port>.' }
        Write-Host ''
        Write-Host "The control plane's enrollment endpoint, as host:port. It is the address"
        Write-Host "this host dials, printed by ``fleetctl enroll mint`` -- not this host's own."
        $Control = Read-FleetAnswer -Question 'Control endpoint' -Default '' -NeedsFlag '-Control'
    }
    if (-not $CaFingerprint) {
        # Checked before anything is downloaded: an invocation that cannot
        # possibly enroll should cost nothing, rather than leaving a binary
        # installed on a host that never joined the fleet.
        if (-not $console) {
            throw @'
-Token requires -CaFingerprint <hex>.

`fleet-agent enroll` refuses to run unpinned. Without the fingerprint,
anything that can answer on the network collects the token, and the token is
the only thing between an attacker and a fleet identity.

Get it from the control host with: fleetctl ca fingerprint
'@
        }
        Write-Host ''
        Write-Host "The fleet CA's SHA-256 fingerprint, from ``fleetctl ca fingerprint``."
        Write-Host 'Enrollment refuses to run without it: unpinned, anything that can answer'
        Write-Host 'on the network collects the token.'
        $CaFingerprint = Read-FleetAnswer -Question 'CA fingerprint' -Default '' -NeedsFlag '-CaFingerprint'
    }
}

if (-not $binaryOnly -and -not $Listen) {
    if ($console) {
        $Listen = Read-FleetListen -Mtls $mtls
    } elseif ($mtls) {
        $Listen = $MtlsDefaultListen
    } else {
        throw @"
-Listen is required with -NoMtls: it is the address the agent binds, and there is
no safe default for it. 0.0.0.0 binds every interface on this host, which the
agent refuses with mTLS off.

Pick one of this host's own addresses on a network that authenticates its peers
-- a tailnet address, an RFC 1918 address -- or 127.0.0.1 for a host that is
only reached from itself.
"@
    }
}

if ($Name -and -not (Test-FleetSandboxName -SandboxName $Name)) {
    throw (@("$Name is not a name this fleet can hold.") + (Get-FleetNameRule) -join [Environment]::NewLine)
}

# Before the download, not after it. The daemon checks this too and stays the
# authority, but through the service control manager its refusal reaches an
# operator as error 1053, "the service did not respond in a timely fashion" --
# which is failure 6 in #100, three steps removed from the answer that caused it.
if (-not $binaryOnly) {
    $refusal = Get-FleetListenRefusal -ListenAddress $Listen -Mtls $mtls
    if ($refusal) {
        throw (@("$Listen is not an address this agent will start on: $refusal.", '') +
            (Get-FleetListenRemedy) -join [Environment]::NewLine)
    }
}

# The other half of item 8, and a question rather than a derivation.
#
# -Listen is the socket bound here. -Address is what the control plane dials,
# and it becomes a subject alternative name on the certificate this host is
# issued. They are often the same and are not always: a host reached by a
# MagicDNS name serves on the address that name resolves to, and deriving one
# from the other would ask the control plane to certify an address the token
# never authorized -- which it refuses, turning an install that worked into one
# that does not.
#
# A token minted with `fleetctl enroll mint -Address` already names what the
# control plane dials, and both the certificate and the fleet entry come from
# the token then. What this question is for is the token that authorized none:
# enrollment records the address the agent asked for, and a host that asked for
# nothing is registered with no address at all.
if (-not $binaryOnly -and $mtls -and $Address.Count -eq 0 -and $console) {
    Write-Host ''
    Write-Host 'Which address will the control plane dial this host by?'
    Write-Host ''
    Write-Host 'This is not the address above. That one is the socket bound here; this is'
    Write-Host 'what your workstation connects to, and it becomes a name on the certificate'
    Write-Host 'this host is issued.'
    Write-Host ''
    Write-Host 'Leave it blank if the token already names it. `fleetctl enroll mint` prints'
    Write-Host 'the addresses a token authorizes, and both the certificate and the fleet'
    Write-Host 'entry come from those. Fill it in if it authorized none, or this host is'
    Write-Host 'registered with no address and nothing can dial it.'
    $dialled = Read-Host -Prompt 'Dialled as (blank for whatever the token authorized)'
    if ($dialled) { $Address = @($dialled.Trim()) }
}

# Not asked with mTLS on: the token normally reserves the name, and the control
# plane refuses a name other than the one its token authorizes -- so a host that
# filled this in from its own computer name would be asking to be refused. The
# assigned name is read back out of the config enrollment writes.
if (-not $binaryOnly -and -not $mtls -and -not $Name) {
    $suggested = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'fleet-agent' }
    if ($console) {
        Write-Host ''
        Write-Host 'What should this host be called in the fleet? It is the name you will select'
        Write-Host 'it by, and the name every audit record it writes is stamped with.'
        while ($true) {
            $Name = Read-FleetAnswer -Question 'Sandbox name' -Default $suggested -NeedsFlag '-Name'
            if (Test-FleetSandboxName -SandboxName $Name) { break }
            foreach ($line in Get-FleetNameRule) { Write-Host "  $line" }
        }
    } else {
        $Name = $suggested
    }
}

if ($Service -eq 'auto') {
    $Service = if ($elevated -and -not $binaryOnly) { 'yes' } else { 'no' }
    if ($console -and $Service -eq 'yes') {
        Write-Host ''
        Write-Host 'Register fleet-agent to start at logon? Without this the agent is installed'
        Write-Host 'and configured but nothing is running, and you start it by hand.'
        $answer = Read-FleetAnswer -Question 'Register and start it? [yes/no]' -Default 'yes' -NeedsFlag '-Service'
        $Service = if ($answer -match '^(y|yes)$') { 'yes' } else { 'no' }
    }
}
if ($binaryOnly -and $Service -eq 'yes') {
    # Said rather than silently dropped: -Service yes is an instruction, and an
    # instruction this run cannot carry out should not look like one it did.
    Write-Warn 'There is no configured agent to register, so nothing will be. Pass -Token or -NoMtls.'
    $Service = 'no'
}
if ($Service -eq 'yes' -and -not $elevated) {
    throw 'Registering the agent to start at logon requires an elevated PowerShell session: it writes a Scheduled Task or a Windows service and creates directories under ProgramData.'
}

if (-not $InstallDir) {
    # A location the account the agent runs as can read. `service install`
    # registers the path this puts the binary at and never copies it, so a
    # binary left where it was downloaded -- a Desktop, a Downloads folder --
    # is a registration that succeeds and a service that fails every start.
    # That is item 3 in #100.
    $InstallDir = if ($elevated) {
        Join-Path $env:ProgramFiles 'fleet'
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\fleet'
    }
}
if (-not $ConfigDir) {
    $ConfigDir = if ($env:FLEET_CONFIG_DIR) {
        Join-Path $env:FLEET_CONFIG_DIR 'agent'
    } elseif ($elevated) {
        Join-Path $env:ProgramData 'fleet'
    } else {
        Join-Path $env:APPDATA 'fleet\agent'
    }
}
$systemConfigDir = Join-Path $env:ProgramData 'fleet'
$target     = Join-Path $InstallDir 'fleet-agent.exe'
$configPath = Join-Path $ConfigDir 'agent.yaml'

Write-Host ''
Write-Host '  fleet-agent, on this host:'
Write-Host ''
if ($Version -eq 'latest') {
    # Not resolved yet, deliberately: asking the API which release is latest is
    # a network call, and a run that is about to be answered "no" at the prompt
    # below should not have made one.
    Write-Host '    release        latest (resolved when it downloads)'
} else {
    Write-Host "    release        $Version"
}
Write-Host "    platform       windows/$arch"
Write-Host "    binary         $target"
if ($binaryOnly) {
    Write-Host '    config         none: the binary and nothing else'
} else {
    Write-Host "    config         $configPath"
    if ($mtls) {
        Write-Host "    authenticates  by certificate, enrolling against $Control"
        Write-Host '    name           assigned by the control plane'
    } else {
        Write-Host '    authenticates  nobody: the network is what keeps callers out'
        Write-Host "    name           $Name"
    }
    Write-Host "    listens on     $Listen"
    if ($Address.Count -gt 0) {
        Write-Host "    dialled as     $($Address -join ', ')"
    }
}
Write-Host "    service        $(if ($Service -eq 'yes') { 'registered and started' } else { 'not registered' })"

if ($DryRun) {
    Write-Host ''
    Write-Host '  Dry run: nothing was downloaded, written or registered.'
    if (-not $binaryOnly) {
        $choices = Get-FleetAddressChoice -Candidate (Get-FleetHostAddress) -Mtls $mtls
        $dialled = Get-FleetWorkstationAddress -ListenAddress $Listen -Advertised $Address -Choice $choices
        Write-Host ''
        foreach ($line in Get-FleetNextStep -SandboxName $Name -WorkstationAddress $dialled -Mtls $mtls) {
            Write-Host "  $line"
        }
    }
    return
}

if ($console) {
    Write-Host ''
    $go = Read-FleetAnswer -Question 'Proceed? [yes/no]' -Default 'yes' -NeedsFlag '-NonInteractive'
    if ($go -notmatch '^(y|yes)$') { throw 'Stopped at your request; nothing was changed.' }
}

$resolved    = Resolve-ReleaseVersion -Requested $Version
$archive     = "fleet-agent_windows_$arch.zip"
$archiveUrl  = "$BaseUrl/download/$resolved/$archive"
$checksumUrl = "$BaseUrl/download/$resolved/checksums.txt"

$work = Join-Path ([IO.Path]::GetTempPath()) ("fleet-" + [Guid]::NewGuid().ToString('n'))
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

    $binary = Join-Path $work 'fleet-agent.exe'
    if (-not (Test-Path $binary)) { throw 'Archive did not contain fleet-agent.exe.' }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $binary -Destination $target -Force

    Write-Step "installed $target"

    # Put the install directory on PATH for the appropriate scope, so the
    # operator can run `fleet-agent` without qualifying it.
    $scope    = if ($elevated) { 'Machine' } else { 'User' }
    $current  = [Environment]::GetEnvironmentVariable('Path', $scope)
    if ($current -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable('Path', "$current;$InstallDir", $scope)
        Write-Step "added $InstallDir to the $scope PATH (restart your shell to pick it up)"
    }

    if ($binaryOnly) {
        Write-Host @"

  Installed. Nothing else was configured: no config, no CA, no certificate, no
  service. That is what this invocation asked for -- nothing said which posture
  to configure, and there was no console to ask on.

  Run it again from a PowerShell prompt and it will ask, offering the addresses
  this host actually has:

    irm $ScriptUrl | iex

  Or say it outright. For a network that authenticates its own peers -- a
  tailnet, a WireGuard mesh, a tight VPC:

    `$s = irm $ScriptUrl
    & ([scriptblock]::Create(`$s)) -NoMtls -Listen <this-host-address>:$DefaultPort

  With mTLS off this agent authenticates nobody: anyone who can reach its port
  can run commands on this host. It refuses to serve on an address that is
  neither loopback nor private for exactly that reason. See docs/security.md.

  Otherwise, enroll against a fleet CA so both ends carry a certificate:

    `$s = irm $ScriptUrl
    & ([scriptblock]::Create(`$s)) -Token <enrollment-token> ``
        -Control <control-host:9443> -CaFingerprint <sha256-of-the-fleet-CA>

  Mint a token on the control host with: fleetctl enroll mint
  Read its CA fingerprint with:          fleetctl ca fingerprint
"@
        return
    }

    # Said whether or not roots were given, because it is true either way: the
    # default config has exec on, and an agent that runs commands is not
    # confined by a path check. See docs/security.md.
    Write-Warn 'Exec is enabled, so allowed_roots is not enforced: this agent can read and write every path its account can. Set exec.enabled to false in the config to make -Root a real jail.'

    if ($mtls) {
        $enrollArgs = @(
            'enroll',
            '--token', $Token,
            '--control', $Control,
            '--ca-fingerprint', $CaFingerprint,
            '--listen', $Listen,
            '--dir', $ConfigDir
        )
        if ($Name) { $enrollArgs += @('--name', $Name) }
        foreach ($a in $Address) { $enrollArgs += @('--address', $a) }
        foreach ($r in $Root) { $enrollArgs += @('--root', $r) }

        Write-Step "enrolling with $Control"
        & $target @enrollArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Enrollment failed with exit code $LASTEXITCODE, so nothing was configured. The binary is installed at $target; re-run once the cause above is fixed."
        }

        # The name the control plane assigned, which is what the fleet knows
        # this host by. Read out of the file enrollment just wrote rather than
        # assumed from -Name, because a token that reserved a name overrides
        # what was asked for.
        $written = Select-String -Path $configPath -Pattern '^name:\s*(.*)$' | Select-Object -First 1
        if ($written) { $Name = $written.Matches[0].Groups[1].Value.Trim().Trim('"') }
    } else {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
        if (Test-Path $configPath) {
            Copy-Item -Path $configPath -Destination "$configPath.bak" -Force
            Write-Warn "$configPath already existed; the previous one is at $configPath.bak"
        }
        $yaml = New-Object Collections.Generic.List[string]
        $yaml.Add("# fleet-agent configuration, written by install.ps1 on $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')).")
        $yaml.Add('#')
        $yaml.Add('# Every setting, and what each one costs, is in examples/agent.yaml.')
        $yaml.Add("name: `"$($Name -replace '\\', '\\\\' -replace '"', '\"')`"")
        $yaml.Add("listen: `"$Listen`"")
        $yaml.Add('tls:')
        $yaml.Add('  # THIS AGENT AUTHENTICATES NOBODY. It serves plaintext: no client')
        $yaml.Add('  # certificate is demanded, none is presented, and nothing is encrypted by')
        $yaml.Add('  # this product. Whatever authenticates the caller is the network. The')
        $yaml.Add('  # daemon refuses to bind an address that is neither loopback nor private')
        $yaml.Add('  # for that reason. See docs/security.md.')
        $yaml.Add('  enabled: false')
        if ($Root.Count -gt 0) {
            $yaml.Add('allowed_roots:')
            foreach ($r in $Root) { $yaml.Add("  - `"$($r -replace '\\', '\\\\')`"") }
        }
        $yaml.Add('audit:')
        $yaml.Add('  enabled: true')
        if ($ConfigDir -ne $systemConfigDir) {
            # Relative to this file's own directory, which is what the daemon
            # resolves them against. Written only away from the system path,
            # because there the platform defaults are the right answers and are
            # what `service install` grants the service account.
            $yaml.Add('  path: "logs/audit.jsonl"')
            $yaml.Add('state_dir: "state"')
        }
        Set-Content -Path $configPath -Value $yaml -Encoding ascii
        Write-Step "wrote $configPath"
    }

    if ($Service -eq 'yes') {
        # `service install` prints which mechanism it chose, the account, and
        # what that account costs: a task stops at logout, and a service in
        # session 0 cannot see a per-user toolchain.
        Write-Step 'registering the agent to start at logon'
        $attempt = 1
        while ($true) {
            $out = & $target service install --config $configPath 2>&1
            foreach ($line in $out) { Write-Host $line }
            if ($LASTEXITCODE -eq 0) { break }

            $text = ($out | Out-String)
            if ($attempt -lt 5 -and (Test-FleetTransientRegistration -Output $text)) {
                # Transient, and it says so rather than handing back an SCM
                # string. The entry clears when the last handle to it closes.
                Write-Step "the previous service definition is still being removed; waiting, then trying again ($attempt of 5)"
                Start-Sleep -Seconds 3
                $attempt++
                continue
            }
            # Not swallowed. Until #100 a registration that failed was a warning
            # and the installer went on to report success, which left an
            # operator with a host they believed had joined the fleet and a
            # service that had never been written.
            throw @"
Registering the service failed, so this host is not running the agent.
The binary and the config are in place: fix the cause above and run
  $target service install --config $configPath
"@
        }

        & $target service start
        if ($LASTEXITCODE -ne 0) {
            throw @"
The service was registered and would not start.
Read ``$target service status`` for what the daemon recorded, fix it, and run
  $target service start
"@
        }

        # `service start` returns when the manager has accepted the start, not
        # when the daemon is serving. Everything that can still go wrong goes
        # wrong after that -- a listen address the guard refuses, a port already
        # bound, a config the account cannot read -- and each leaves a
        # registered service and nothing listening, which is the outcome this
        # installer must never report as success. Since #98 a start that failed
        # writes down why, and `service status` reads it back.
        Write-Step 'waiting for the agent to come up'
        $running = $false
        $status = ''
        for ($i = 0; $i -lt 30; $i++) {
            $status = (& $target service status 2>&1 | Out-String)
            if ($status -match 'service fleet-agent: running') { $running = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $running) {
            Write-Host ''
            Write-Host 'The service was registered and started, and it is not running.'
            Write-Host 'This is what `fleet-agent service status` says about it:'
            Write-Host ''
            Write-Host $status
            throw @"
The agent did not come up, so this installation is not finished. Nothing is
undone: fix the cause above and run
  $target service start
"@
        }
        Write-Step 'the service manager reports it running'

        if (Test-FleetListener -ListenAddress $Listen) {
            Write-Step "$Listen is accepting connections"
        } else {
            throw @"
The agent is running and nothing is answering at $Listen.
Check the address in $configPath against the addresses this host has, and read
  $target service status
"@
        }
        Write-Host ''
        Write-Host '  Installed, configured, running.'
    } else {
        Write-Host ''
        Write-Host '  Installed and configured. Nothing is running: no service was registered.'
        Write-Host ''
        Write-Host '  Register and start it from an elevated PowerShell with:'
        Write-Host ''
        Write-Host "    $target service install --config $configPath"
        Write-Host "    $target service start"
    }

    $choices = Get-FleetAddressChoice -Candidate (Get-FleetHostAddress) -Mtls $mtls
    $dialled = Get-FleetWorkstationAddress -ListenAddress $Listen -Advertised $Address -Choice $choices
    Write-Host ''
    foreach ($line in Get-FleetNextStep -SandboxName $Name -WorkstationAddress $dialled -Mtls $mtls) {
        Write-Host "  $line"
    }
    if ((Get-FleetAddressClass -HostText (Split-FleetEndpoint -Endpoint $Listen).Host) -eq 'loopback') {
        Write-Host ''
        Write-Host "  $Listen is loopback, so only this machine can reach the agent. Run the"
        Write-Host '  MCP server here, or re-run with a listen address on a network your'
        Write-Host '  workstation is on.'
    }
} finally {
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
