#!/bin/sh
# fleet-agent installer.
#
#   curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh | sh
#
# Downloads the release binary for this platform, verifies its SHA-256 against
# the release checksum file, installs it where the service account can read it,
# writes a config, registers a system service, starts it, and checks that it
# came up before saying so.
#
# It asks when it has a terminal and has not been told. Every flag below still
# works exactly as it did, and that is the path CI and provisioning scripts
# take: interactive is what happens when a terminal is present *and* a required
# answer is missing. An installer that can only be driven by hand cannot be
# scripted, and this product is installed by scripts.
#
# No prompt has an unsafe default, and the listen address is why the rule
# exists: 0.0.0.0 is the obvious thing to type, and with mTLS off it is exactly
# what the agent's own guard refuses — which reaches an operator as a service
# that will not start, several steps after the decision that caused it. So the
# addresses this host actually has are enumerated and offered, labelled by what
# can reach them, with a tailnet address first.
#
# Piping a script from the network into a shell is trust-on-first-use no matter
# how careful the script is. This one at least refuses to install an artifact
# whose checksum does not match the one published alongside it, and it always
# pins the control-plane CA — enrollment will not run without a fingerprint.

set -eu

REPO="axelmierczuk/fleet-mcp"
BASE_URL="https://github.com/${REPO}/releases"
API_URL="https://api.github.com/repos/${REPO}/releases"
# Where this script is published, for the invocations it prints back.
INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/${REPO}/main/install.sh"

# The port an address is offered on when the operator picks one from the menu.
# It is internal/agent's DefaultListen port and what the MCP server's registry
# records by default.
DEFAULT_PORT="8722"

# What the scripted mTLS path listens on when no --listen is given. It stays
# what it has always been: `fleetctl enroll mint` prints this exact invocation,
# and a wildcard bind is an ordinary deployment for an agent that authenticates
# every caller by certificate. The guard that refuses it applies only with mTLS
# off, and that posture has no default at all — see ask_listen and check_listen.
MTLS_DEFAULT_LISTEN="0.0.0.0:8722"

VERSION="latest"
INSTALL_DIR=""
CONFIG_DIR=""
TOKEN=""
CONTROL=""
LISTEN=""
NAME=""
CA_FINGERPRINT=""
INSTALL_SERVICE="auto"
ALLOWED_ROOTS=""
ADVERTISED=""
SKIP_CHECKSUM="no"
# The posture, once it is known: "yes" (mTLS), "no" (the network authenticates),
# or "" (nobody has said, and there is nothing to ask with).
MTLS=""
# Set when nothing said which posture to configure and there is no terminal to
# ask on: the binary is installed and nothing else is touched.
BINARY_ONLY="no"
INTERACTIVE="auto"
DRY_RUN="no"
# Where a question is asked: "stdin", "tty", or "" for a run that cannot ask.
TERMINAL=""

log()  { printf '  %s\n' "$*" >&2; }
say()  { printf '%s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
Usage: install.sh [options]

With a terminal and no options, it asks: how callers are authenticated, which
address to serve on, and whether to register a service. With the options below
it asks nothing, which is the path `curl | sh -s -- ...` and CI take.

Options:
  --token <token>          Enrollment token from `fleetctl enroll mint`.
                           Selects mTLS: the host enrolls after installation,
                           and --control and --ca-fingerprint become required.
  --control <host:port>    Control-plane enrollment endpoint.
  --ca-fingerprint <hex>   SHA-256 fingerprint of the control-plane CA to pin,
                           from `fleetctl ca fingerprint`. Required with
                           --token: enrollment refuses to run unpinned.
  --no-mtls                Configure an agent that authenticates nobody, for a
                           network that authenticates its own peers. --listen
                           becomes required: there is no safe default for it.
  --listen <addr:port>     Address the agent serves gRPC on. With --token it
                           defaults to 0.0.0.0:8722; with --no-mtls it has no
                           default and a public or wildcard address is refused.
  --address <host:port>    Address the control plane dials this host by, which
                           is not the same thing as --listen. Repeatable; it
                           becomes a subject alternative name on the issued
                           certificate. Defaults to --listen when that names a
                           concrete address.
  --name <name>            Sandbox name. With --token, only for a token that
                           reserved none; the control plane refuses a name
                           other than the one its token authorizes.
  --root <path>            Filesystem root the agent may access. Repeatable.
                           Enforced only when exec.enabled is false in the
                           config: a caller that can run commands reaches any
                           path without going through FileService.
  --version <vX.Y.Z>       Release to install (default: latest).
  --base-url <url>         Where the release assets are, for a mirror of the
                           GitHub release layout. The checksum check is
                           unchanged: the mirror publishes checksums.txt too,
                           and a mismatch still refuses to install.
  --install-dir <path>     Install prefix (default: /usr/local/bin, or
                           ~/.local/bin for an unprivileged install).
  --config-dir <path>      Directory to write agent.yaml into (default: the
                           system config directory when run as root, else the
                           per-user enrollment directory).
  --service <yes|no|auto>  Register a system service (default: auto, meaning
                           yes when running as root).
  --non-interactive        Never ask, even with a terminal. A missing answer is
                           then an error naming the flag that supplies it.
  --dry-run                Resolve everything, print the plan, change nothing.
  --skip-checksum          Skip checksum verification. Do not use this.
  -h, --help               Show this help.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)           TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --control)         CONTROL="${2:?--control needs a value}"; shift 2 ;;
    --ca-fingerprint)  CA_FINGERPRINT="${2:?--ca-fingerprint needs a value}"; shift 2 ;;
    --no-mtls)         MTLS="no"; shift ;;
    --listen)          LISTEN="${2:?--listen needs a value}"; shift 2 ;;
    --address)         ADVERTISED="${ADVERTISED} ${2:?--address needs a value}"; shift 2 ;;
    --name)            NAME="${2:?--name needs a value}"; shift 2 ;;
    --root)            ALLOWED_ROOTS="${ALLOWED_ROOTS} ${2:?--root needs a value}"; shift 2 ;;
    --version)         VERSION="${2:?--version needs a value}"; shift 2 ;;
    --base-url)        BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
    --install-dir)     INSTALL_DIR="${2:?--install-dir needs a value}"; shift 2 ;;
    --config-dir)      CONFIG_DIR="${2:?--config-dir needs a value}"; shift 2 ;;
    --service)         INSTALL_SERVICE="${2:?--service needs a value}"; shift 2 ;;
    --non-interactive) INTERACTIVE="no"; shift ;;
    --dry-run)         DRY_RUN="yes"; shift ;;
    --skip-checksum)   SKIP_CHECKSUM="yes"; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "unknown option: $1 (try --help)" ;;
  esac
done

case "$INSTALL_SERVICE" in
  yes|no|auto) ;;
  *) die "--service takes yes, no or auto (got $INSTALL_SERVICE)" ;;
esac

if [ -n "$TOKEN" ] && [ "$MTLS" = "no" ]; then
  die "--token and --no-mtls ask for opposite postures: --token enrolls this host
against a CA so both ends present a certificate, and --no-mtls configures an
agent that authenticates nobody. Pass one."
fi
if [ -n "$TOKEN" ]; then
  MTLS="yes"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------- asking ------

# detect_terminal decides whether there is somebody to ask, and where.
#
# `curl | sh` hands this script its own source on stdin, so a pipe on stdin
# says nothing about whether an operator is watching: the controlling terminal
# is /dev/tty whatever stdin is. It is only used when stderr is a terminal too,
# because a host that has a controlling terminal and nobody in front of it — a
# provisioning run, a cron job, a CI step — must take the non-interactive path
# rather than block on a question no one will answer. That is #73's shape: a
# prompt reading a terminal that never replies.
detect_terminal() {
  TERMINAL=""
  [ "$INTERACTIVE" = "no" ] && return 0
  if [ -t 0 ]; then
    TERMINAL="stdin"
    return 0
  fi
  # In a subshell: a failed redirection on `exec` ends a non-interactive shell
  # outright, and this is a question about the host, not a fatal condition.
  if [ -t 2 ] && ( exec 3</dev/tty ) 2>/dev/null; then
    TERMINAL="tty"
  fi
  return 0
}

# read_answer reads one line from the terminal, or fails when there is none.
#
# A failure is end of input — the terminal closed, or a fixture that answers
# nothing and then goes away — and it is never itself an answer. Every caller
# turns it into a refusal naming the flag that would have supplied one, because
# a prompt that fell back to its default at end of input would be a prompt with
# an unsafe default reached by another road.
read_answer() {
  case "$TERMINAL" in
    stdin) IFS= read -r _line || return 1 ;;
    tty)   IFS= read -r _line < /dev/tty || return 1 ;;
    *)     return 1 ;;
  esac
  printf '%s\n' "$_line"
}

trim() { printf '%s\n' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }

# ask puts one question and prints the answer on stdout. The prompt goes to
# stderr with everything else this script says, so stdout stays the answer.
#
# needs_flag names what would have answered it without a terminal, so the
# refusal an unattended run gets is the command line it was missing.
ask() {
  _question="$1"
  _default="$2"
  _needs_flag="$3"
  while :; do
    if [ -n "$_default" ]; then
      printf '%s [%s]: ' "$_question" "$_default" >&2
    else
      printf '%s: ' "$_question" >&2
    fi
    if ! _reply="$(read_answer)"; then
      printf '\n' >&2
      die "no answer: the terminal closed while waiting.
Pass ${_needs_flag} to answer this without a terminal."
    fi
    _reply="$(trim "$_reply")"
    if [ -n "$_reply" ]; then
      printf '%s\n' "$_reply"
      return 0
    fi
    if [ -n "$_default" ]; then
      printf '%s\n' "$_default"
      return 0
    fi
    say "  this one has no default; an answer is needed."
  done
}

# ask_optional is ask for a question that may be left unanswered. End of input
# is still a refusal -- see read_answer -- but a blank line is an answer here,
# and the caller decides what an unanswered one means.
ask_optional() {
  _question="$1"
  _needs_flag="$2"
  printf '%s: ' "$_question" >&2
  if ! _reply="$(read_answer)"; then
    printf '\n' >&2
    die "no answer: the terminal closed while waiting.
Pass ${_needs_flag} to answer this without a terminal."
  fi
  trim "$_reply"
}

# require answers with a flag when there is nobody to ask.
require() {
  [ -n "$TERMINAL" ] && return 0
  die "$1"
}

# ------------------------------------------------------------- platform ------

detect_os() {
  os="$(uname -s)"
  case "$os" in
    Linux)  echo linux ;;
    Darwin) echo darwin ;;
    FreeBSD) echo freebsd ;;
    *) die "unsupported operating system: $os (Windows hosts use install.ps1)" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported architecture: $arch" ;;
  esac
}

# system_config_dir mirrors internal/agent.SystemConfigDir. The daemon is the
# authority; this has to agree with it so that what the installer writes is what
# `serve` and `service install` later discover.
system_config_dir() {
  case "$1" in
    darwin) echo "/Library/Application Support/fleet" ;;
    *)      echo "/etc/fleet" ;;
  esac
}

# user_config_dir is where `fleet-agent enroll` writes without elevation.
user_config_dir() {
  # registry.ConfigDir's order, so the directory this writes into is the one
  # `fleet-agent serve` discovers: the explicit variable, then XDG, then the
  # home default. The pre-rebrand fallback that function also honours is not
  # repeated here -- it is for a host that already holds a sandboxd-era
  # enrollment, and this writes a new one.
  if [ -n "${FLEET_CONFIG_DIR:-}" ]; then
    echo "${FLEET_CONFIG_DIR}/agent"
  elif [ -n "${XDG_CONFIG_HOME:-}" ]; then
    echo "${XDG_CONFIG_HOME}/fleet/agent"
  else
    echo "${HOME}/.config/fleet/agent"
  fi
}

# check_name refuses a sandbox name the fleet would refuse.
#
# registry.CheckName is the authority and applies the same rule -- printable
# ASCII with no spaces, nothing starting with the handle prefix, 128 bytes at
# most. It is worth applying here because this script *prints a command* built
# from the name: `fleetctl add build box --address ...` is not a command, and an
# operator finds that out by pasting it.
check_name() {
  case "$1" in
    "" | sbx_*) return 1 ;;
    *[[:space:]]*) return 1 ;;
  esac
  [ "${#1}" -le 128 ] || return 1
  # Whatever is left after deleting the printable, non-space ASCII is what the
  # rule does not admit. In the C locale, so the range means the bytes it says.
  [ -z "$(printf '%s' "$1" | LC_ALL=C tr -d '\041-\176')" ]
}

name_rule() {
  say "A sandbox name is printable ASCII with no spaces, at most 128 bytes, and"
  say "does not start with sbx_. It is typed on a command line and printed in a"
  say "table -- including in the \`fleetctl add\` line this prints at the end."
}

default_name() {
  _host="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo "")"
  _host="${_host%%.*}"
  # Printable ASCII with no spaces, which is registry.CheckName's rule, so the
  # `fleetctl add` line this prints is one that runs.
  _host="$(printf '%s' "$_host" | tr -c 'A-Za-z0-9._-' '-')"
  if [ -z "$_host" ] || [ "$_host" = "-" ]; then
    echo "fleet-agent"
  else
    echo "$_host"
  fi
}

# --------------------------------------------------------- addresses ---------

# raw_addresses prints "<address> <interface>" for every IPv4 address this host
# has.
#
# IPv4 only, deliberately. An IPv6 address needs brackets inside host:port, and
# the addresses this question is about — a tailnet address, an RFC 1918 LAN
# address — are v4 on every host. "something else" at the menu takes anything,
# including a bracketed v6 address.
raw_addresses() {
  if have ip; then
    ip -o -4 addr show 2>/dev/null | awk '
      { for (i = 1; i < NF; i++) if ($i == "inet") { split($(i + 1), parts, "/"); print parts[1], $2 } }'
  elif have ifconfig; then
    ifconfig -a 2>/dev/null | awk '
      /^[^[:space:]]/ { iface = $1; sub(/:$/, "", iface) }
      $1 == "inet" { addr = $2; sub(/^addr:/, "", addr); if (addr != "") print addr, iface }'
  fi
}

# tailscale_ip is this host's tailnet address, when there is a tailscale here to
# ask. The CLI is asked rather than the interface guessed, because the interface
# is called tailscale0 on Linux and utun<n> on macOS, where it is
# indistinguishable from any other tunnel.
tailscale_ip() {
  if have tailscale; then
    tailscale ip -4 2>/dev/null | head -n 1
  fi
}

# classify_address names what can reach an address, in internal/agent's terms.
# The daemon's CheckListenPosture is the authority; this exists so the question
# can be answered before a service is written rather than after one fails.
classify_address() {
  case "$1" in
    0.0.0.0|::|"")                                        echo wildcard ;;
    127.*|localhost)                                      echo loopback ;;
    10.*|192.168.*)                                       echo private ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*)                echo private ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo cgnat ;;
    169.254.*)                                            echo linklocal ;;
    *)                                                    echo public ;;
  esac
}

host_of() {
  case "$1" in
    \[*\]:*) printf '%s\n' "$1" | sed 's/^\[\(.*\)\]:.*$/\1/' ;;
    *:*)     printf '%s\n' "${1%:*}" ;;
    *)       printf '%s\n' "$1" ;;
  esac
}

port_of() {
  case "$1" in
    *:*) printf '%s\n' "${1##*:}" ;;
    *)   printf '\n' ;;
  esac
}

# check_listen refuses a listen address the daemon would refuse, and says the
# same three things the daemon says about it.
#
# The daemon checks this too — twice, in Config.Validate and in agent.New — and
# it stays the authority. What it cannot do is refuse before a service exists:
# through a service manager its refusal arrives as "the service did not respond
# in a timely fashion", several steps after the answer that caused it. This is
# the same rule applied while the operator is still being asked.
check_listen() {
  [ "$MTLS" = "no" ] || return 0
  case "$(classify_address "$(host_of "$1")")" in
    wildcard)
      LISTEN_REFUSAL="$1 binds every interface on this host, including any public one"
      return 1 ;;
    public)
      LISTEN_REFUSAL="$1 is a public address"
      return 1 ;;
    *) return 0 ;;
  esac
}

listen_remedy() {
  say "With mTLS off this agent authenticates nobody: anyone who can reach this"
  say "port can run commands on this host as the account it runs as. Either:"
  say "  - enroll this host, so callers are authenticated by certificate:"
  say "    re-run with --token, --control and --ca-fingerprint; or"
  say "  - listen on a loopback or private address — a tailnet or VPC address is"
  say "    what this posture is for."
}

# ---------------------------------------------------------- the questions ----

ask_posture() {
  if [ -n "$MTLS" ]; then
    return 0
  fi
  if [ -z "$TERMINAL" ]; then
    # Nobody said, and there is nothing to ask with. This is `curl | sh` with no
    # flags at all — the "put the agent on the host" step in the README — and it
    # has always installed the binary and stopped. It still does: an install
    # that started guessing at a posture would be guessing about who may run
    # commands on this machine.
    BINARY_ONLY="yes"
    return 0
  fi

  say ""
  say "How should callers of this agent be authenticated?"
  say ""
  say "  1) mTLS. This host enrolls against your fleet CA and both ends present a"
  say "     certificate. Needs an enrollment token, the control address and the CA"
  say "     fingerprint — \`fleetctl enroll mint\` on your workstation prints all three."
  say "  2) None. The agent authenticates nobody, and whatever keeps people out is"
  say "     the network: a tailnet, a WireGuard mesh, a VPC with tight security"
  say "     groups. Anyone who can reach its port can run commands on this host."
  say ""
  while :; do
    _posture="$(ask "Authentication [1 or 2]" "" "--token or --no-mtls")"
    case "$_posture" in
      1|mtls|mTLS|MTLS) MTLS="yes"; return 0 ;;
      2|none|no|None)   MTLS="no";  return 0 ;;
      *) say "  answer 1 or 2." ;;
    esac
  done
}

ask_enrollment() {
  [ "$MTLS" = "yes" ] || return 0

  if [ -z "$TOKEN" ]; then
    require "--token is required to enroll, and there is no terminal to ask on"
    TOKEN="$(ask "Enrollment token" "" "--token")"
  fi
  if [ -z "$CONTROL" ]; then
    require "--token requires --control <host:port>"
    say ""
    say "The control plane's enrollment endpoint, as host:port. It is the address"
    say "this host dials, printed by \`fleetctl enroll mint\` — not this host's own."
    CONTROL="$(ask "Control endpoint" "" "--control")"
  fi
  if [ -z "$CA_FINGERPRINT" ]; then
    # Checked here rather than at the enroll step, so an invocation that cannot
    # possibly enroll costs nothing. Discovering it after the download leaves a
    # binary installed on a host that never joined the fleet, which is the worst
    # of both outcomes.
    require "--token requires --ca-fingerprint <hex>

\`fleet-agent enroll\` refuses to run unpinned. Without the fingerprint,
anything that can answer on the network collects the token, and the token is
the only thing between an attacker and a fleet identity.

Get it from the control host with: fleetctl ca fingerprint"
    say ""
    say "The fleet CA's SHA-256 fingerprint, from \`fleetctl ca fingerprint\`."
    say "Enrollment refuses to run without it: unpinned, anything that can answer"
    say "on the network collects the token."
    CA_FINGERPRINT="$(ask "CA fingerprint" "" "--ca-fingerprint")"
  fi
}

# ask_listen offers the addresses this host has, best answer first.
#
# Offered rather than defaulted, and labelled by what can reach them, because
# the whole failure this replaces is an operator typing the obvious thing.
# Tailscale first where there is one: it is a private address on a network that
# already authenticates its peers, which is precisely the posture the no-mTLS
# option is for.
ask_listen() {
  if [ -n "$LISTEN" ]; then
    return 0
  fi
  if [ "$MTLS" = "yes" ] && [ -z "$TERMINAL" ]; then
    LISTEN="$MTLS_DEFAULT_LISTEN"
    return 0
  fi
  require "--listen is required with --no-mtls: it is the address the agent binds, and
there is no safe default for it. 0.0.0.0 binds every interface on this host,
which the agent refuses with mTLS off.

Pick one of this host's own addresses on a network that authenticates its
peers — a tailnet address, an RFC 1918 address — or 127.0.0.1 for a host that
is only reached from itself."

  say ""
  say "Which address should the agent serve on?"
  say ""
  say "This is the socket it binds. It is not necessarily how your workstation"
  say "reaches this host — that is asked separately, and getting the two confused"
  say "produces an agent nobody can dial."
  say ""

  _menu="$(listen_menu)"
  if [ -n "$_menu" ]; then
    printf '%s\n' "$_menu" | awk -F'\t' '{ printf "  %d) %-22s %s\n", NR, $1, $2 }' >&2
  fi
  say "  0) something else"
  say ""

  _default=""
  if [ -n "$_menu" ]; then
    # The first offer that is neither public nor a wildcard. A host whose only
    # address is public gets no default at all rather than a dangerous one --
    # which is the whole rule this question exists to keep: an answer that
    # widens who can reach this agent is never the one you get by pressing
    # return. The rank listen_menu sorted on is what says which those are.
    _default="$(printf '%s\n' "$_menu" | awk -F'\t' '$3 < 6 { print NR; exit }')"
  fi

  while :; do
    _pick="$(ask "Address" "$_default" "--listen")"
    case "$_pick" in
      0)
        _candidate="$(ask "Address as host:port" "" "--listen")"
        ;;
      *[!0-9]*)
        say "  answer with one of the numbers above."
        continue
        ;;
      *)
        _candidate="$(printf '%s\n' "$_menu" | awk -F'\t' -v n="$_pick" 'NR == n { print $1 }')"
        if [ -z "$_candidate" ]; then
          say "  there is no option $_pick."
          continue
        fi
        ;;
    esac
    if [ -z "$(port_of "$_candidate")" ]; then
      _candidate="${_candidate}:${DEFAULT_PORT}"
    fi
    if check_listen "$_candidate"; then
      LISTEN="$_candidate"
      return 0
    fi
    say ""
    say "  refused: ${LISTEN_REFUSAL}."
    listen_remedy
    say ""
  done
}

# listen_menu prints "<address:port><TAB><label><TAB><rank>", best answer first.
listen_menu() {
  _ts="$(tailscale_ip)"
  {
    raw_addresses | while read -r _ip _iface; do
      _class="$(classify_address "$_ip")"
      case "$_class" in
        cgnat)
          if [ -n "$_ts" ] && [ "$_ip" = "$_ts" ]; then
            printf '1\t%s:%s\t%s, Tailscale - private to your tailnet\n' "$_ip" "$DEFAULT_PORT" "$_iface"
          else
            printf '2\t%s:%s\t%s, carrier-grade NAT (100.64.0.0/10) - a tailnet address\n' "$_ip" "$DEFAULT_PORT" "$_iface"
          fi
          ;;
        private)   printf '3\t%s:%s\t%s, private (RFC 1918)\n' "$_ip" "$DEFAULT_PORT" "$_iface" ;;
        loopback)  printf '4\t%s:%s\t%s, loopback - reachable only from this host\n' "$_ip" "$DEFAULT_PORT" "$_iface" ;;
        linklocal) printf '5\t%s:%s\t%s, link-local\n' "$_ip" "$DEFAULT_PORT" "$_iface" ;;
        *)         printf '6\t%s:%s\t%s, PUBLIC - reachable from anywhere that routes to it\n' "$_ip" "$DEFAULT_PORT" "$_iface" ;;
      esac
    done
    # Offered only with mTLS on, where the handshake is the boundary and binding
    # every interface is an ordinary deployment. With mTLS off it is the exact
    # answer this whole question exists to stop being typed, so it is not on the
    # menu — and check_listen refuses it if it is typed anyway.
    if [ "$MTLS" = "yes" ]; then
      printf '7\t0.0.0.0:%s\tevery interface - fine with mTLS, where the handshake is the boundary\n' "$DEFAULT_PORT"
    fi
    # Sorted on the rank, which then becomes the third field: the menu is
    # printed from the first two, and the rank is what says which entries may be
    # the default. Ranks 6 and 7 -- public, and every interface -- never are.
  } | sort -n -k1,1 | awk -F'\t' -v OFS='\t' '{ print $2, $3, $1 }'
}

# ask_advertised is the other half of item 8, and it is a question rather than a
# derivation.
#
# --listen is the socket bound here. --address is what the control plane dials,
# and it becomes a subject alternative name on the certificate this host is
# issued. They are often the same and are not always: a host reached by a
# MagicDNS name serves on the address that name resolves to, and deriving one
# from the other would ask the control plane to certify an address the token
# never authorized -- which it refuses, turning an install that worked into one
# that does not.
#
# So nothing is derived. A token minted with `fleetctl enroll mint --address`
# already names what the control plane dials, and the certificate and the fleet
# entry both come from the token then. What this question is for is the token
# that authorized none: enrollment records the address the agent asked for, and
# a host that asked for nothing is registered with no address at all -- an
# agent in the fleet that nothing can dial, which is the shape #100 item 8
# describes.
ask_advertised() {
  [ "$MTLS" = "yes" ] || return 0
  [ -z "$ADVERTISED" ] || return 0
  [ -n "$TERMINAL" ] || return 0

  say ""
  say "Which address will the control plane dial this host by?"
  say ""
  say "This is not the address above. That one is the socket bound here; this is"
  say "what your workstation connects to, and it becomes a name on the certificate"
  say "this host is issued."
  say ""
  say "Leave it blank if the token already names it. \`fleetctl enroll mint\` prints"
  say "the addresses a token authorizes, and both the certificate and the fleet"
  say "entry come from those. Fill it in if it authorized none, or this host is"
  say "registered with no address and nothing can dial it."
  _dialled="$(ask_optional "Dialled as (blank for whatever the token authorized)" "--address")"
  if [ -n "$_dialled" ]; then
    ADVERTISED="${ADVERTISED} ${_dialled}"
  fi
}

ask_name() {
  [ -n "$NAME" ] && return 0
  if [ "$MTLS" = "yes" ]; then
    # Not asked. The token normally reserves the name, and the control plane
    # refuses a name other than the one its token authorizes — so a host that
    # filled this in from its own hostname would be asking to be refused. The
    # assigned name is read back out of the config enrollment writes.
    return 0
  fi
  _suggested="$(default_name)"
  if [ -z "$TERMINAL" ]; then
    NAME="$_suggested"
    return 0
  fi
  say ""
  say "What should this host be called in the fleet? It is the name you will"
  say "select it by, and the name every audit record it writes is stamped with."
  while :; do
    NAME="$(ask "Sandbox name" "$_suggested" "--name")"
    if check_name "$NAME"; then
      return 0
    fi
    name_rule
  done
}

ask_service() {
  if [ "$INSTALL_SERVICE" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      INSTALL_SERVICE="yes"
    else
      INSTALL_SERVICE="no"
    fi
    # Asked only when it could go either way. Without root there is nothing to
    # ask about: registering a service writes a system service directory and
    # changes file ownership, and `service install` refuses without it.
    if [ -n "$TERMINAL" ] && [ "$INSTALL_SERVICE" = "yes" ]; then
      say ""
      say "Register fleet-agent to start at boot? Without this the agent is installed"
      say "and configured but nothing is running, and you start it by hand."
      _svc="$(ask "Register and start a system service? [yes/no]" "yes" "--service")"
      case "$_svc" in
        y|Y|yes|Yes|YES) INSTALL_SERVICE="yes" ;;
        *)               INSTALL_SERVICE="no" ;;
      esac
    fi
  fi
}

# ------------------------------------------------------------------ fetch ----

fetch() {
  # fetch <url> <output-path>
  if have curl; then
    curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
  elif have wget; then
    wget -q -O "$2" "$1"
  else
    die "neither curl nor wget is available"
  fi
}

fetch_stdout() {
  if have curl; then
    curl -fsSL --retry 3 --retry-delay 2 "$1"
  elif have wget; then
    wget -q -O - "$1"
  else
    die "neither curl nor wget is available"
  fi
}

sha256_of() {
  if have sha256sum; then
    sha256sum "$1" | awk '{print $1}'
  elif have shasum; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo ""
  fi
}

resolve_version() {
  if [ "$VERSION" != "latest" ]; then
    echo "$VERSION"
    return
  fi
  # Ask the API for the latest tag. Parsed with sed rather than jq because a
  # freshly imaged host frequently has neither jq nor python.
  tag="$(fetch_stdout "${API_URL}/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
  [ -n "$tag" ] || die "could not resolve the latest release tag; pass --version explicitly"
  echo "$tag"
}

# ------------------------------------------------------------------ write ----

yaml_string() {
  printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

# write_config writes agent.yaml from the answers.
#
# Only for the no-mTLS posture. The mTLS one is written by `fleet-agent enroll`,
# which has to write it anyway — it is where the certificate, the key and the CA
# bundle land — and two writers of one file is how they disagree.
write_config() {
  mkdir -p "$CONFIG_DIR" 2>/dev/null || die "could not create ${CONFIG_DIR}.
Re-run with sudo, or pass --config-dir <path> for a directory this account owns."

  if [ -f "$CONFIG_PATH" ]; then
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak" \
      || die "could not back up the config already at ${CONFIG_PATH}"
    warn "${CONFIG_PATH} already existed; the previous one is at ${CONFIG_PATH}.bak"
  fi

  {
    printf '# fleet-agent configuration, written by install.sh on %s.\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '#\n'
    printf '# Every setting, and what each one costs, is in examples/agent.yaml.\n'
    printf 'name: %s\n' "$(yaml_string "$NAME")"
    printf 'listen: %s\n' "$(yaml_string "$LISTEN")"
    printf 'tls:\n'
    printf '  # THIS AGENT AUTHENTICATES NOBODY. It serves plaintext: no client\n'
    printf '  # certificate is demanded, none is presented, and nothing is encrypted by\n'
    printf '  # this product. Whatever authenticates the caller is the network. The\n'
    printf '  # daemon refuses to bind an address that is neither loopback nor private\n'
    printf '  # for that reason. See docs/security.md.\n'
    printf '  enabled: false\n'
    if [ -n "$ALLOWED_ROOTS" ]; then
      printf 'allowed_roots:\n'
      # Intentional word splitting: --root is repeatable and the roots are
      # collected into one space-separated string.
      # shellcheck disable=SC2086
      for root in $ALLOWED_ROOTS; do
        printf '  - %s\n' "$(yaml_string "$root")"
      done
    fi
    printf 'audit:\n'
    printf '  enabled: true\n'
    if [ "$CONFIG_DIR" != "$SYSTEM_CONFIG_DIR" ]; then
      # Relative to this file's own directory, which is what the daemon resolves
      # them against. Written only away from the system path, because there the
      # platform defaults — /var/lib/fleet, /var/log/fleet and their macOS
      # counterparts — are the right answers and are what `service install`
      # grants the service account. This is resolveRuntimeDirs' rule, which
      # `enroll` applies to exactly the same choice.
      printf '  path: "logs/audit.jsonl"\n'
      printf 'state_dir: "state"\n'
    fi
  } > "$CONFIG_PATH" || die "could not write ${CONFIG_PATH}.
Re-run with sudo, or pass --config-dir <path> for a directory this account owns."

  log "wrote ${CONFIG_PATH}"
}

# ----------------------------------------------------------------- verify ----

# probe_listener reports whether anything accepts a connection at the address
# the config names.
#
# Deliberately not a claim about gRPC. There is no fleet client on this host —
# the release archive carries the agent alone — so what can be established here
# is that the manager reports a running daemon and that its socket answers.
# `fleetctl add` on the workstation is what proves it serves, and it is the line
# this installer ends by printing.
probe_listener() {
  _host="$(host_of "$LISTEN")"
  _port="$(port_of "$LISTEN")"
  case "$(classify_address "$_host")" in
    wildcard) _host="127.0.0.1" ;;
  esac
  _tries=0
  while [ "$_tries" -lt 20 ]; do
    if have nc; then
      if nc -z "$_host" "$_port" >/dev/null 2>&1; then
        log "${_host}:${_port} is accepting connections"
        return 0
      fi
    elif have bash; then
      if bash -c "exec 3<>/dev/tcp/${_host}/${_port}" >/dev/null 2>&1; then
        log "${_host}:${_port} is accepting connections"
        return 0
      fi
    else
      warn "no nc and no bash here, so nothing checked that ${LISTEN} is answering"
      return 0
    fi
    _tries=$((_tries + 1))
    sleep 1
  done
  die "the agent is running and nothing is answering at ${_host}:${_port}.
Check the address in ${CONFIG_PATH} against the interfaces this host has, and
read \`${BIN_PATH} service status\`."
}

# verify_running is the difference between "the installer finished" and "the
# agent is up".
#
# `service start` returns when the manager has accepted the start, not when the
# daemon is serving: systemd returns once it has forked the process and launchd
# once it has loaded the job. Everything that can still go wrong goes wrong
# after that — a listen address the guard refuses, a port already bound, a
# config the service account cannot read — and each of them leaves a registered
# service and nothing listening, which is the outcome this installer must never
# report as success.
#
# Polled for a fact rather than slept on: `service status` reports what the
# manager says, and since #98 a start that failed writes down why, which the
# same command reads back. So a failure here prints the daemon's own reason.
verify_running() {
  log "waiting for the agent to come up"
  _waited=0
  while :; do
    _status="$("$BIN_PATH" service status 2>&1)" || true
    case "$_status" in
      *"service fleet-agent: running"*)
        log "the service manager reports it running"
        probe_listener
        return 0
        ;;
    esac
    _waited=$((_waited + 1))
    if [ "$_waited" -ge 30 ]; then
      say ""
      say "The service was registered and started, and it is not running."
      say "This is what \`fleet-agent service status\` says about it:"
      say ""
      printf '%s\n' "$_status" >&2
      say ""
      die "the agent did not come up, so this installation is not finished.
Nothing is undone: fix the cause above and run
  ${BIN_PATH} service start"
    fi
    sleep 1
  done
}

# ------------------------------------------------------------- next steps ----

# workstation_address is what your workstation dials this host by. It is not
# always the listen address: a wildcard names no address at all, and loopback
# names one only this host can reach.
workstation_address() {
  if [ -n "$ADVERTISED" ]; then
    # The first --address, which is the one the certificate names first.
    for _addr in $ADVERTISED; do
      printf '%s\n' "$_addr"
      return 0
    done
  fi
  case "$(classify_address "$(host_of "$LISTEN")")" in
    wildcard)
      _best="$(listen_menu | awk -F'\t' 'NR == 1 { print $1 }')"
      if [ -n "$_best" ]; then
        printf '%s\n' "$_best"
      else
        printf 'this-host:%s\n' "$(port_of "$LISTEN")"
      fi
      ;;
    *) printf '%s\n' "$LISTEN" ;;
  esac
}

print_next_steps() {
  _name="$NAME"
  [ -n "$_name" ] || _name="<name>"
  _addr="$(workstation_address)"

  say ""
  if [ "$MTLS" = "yes" ]; then
    say "  Enrollment registered this host, so it is already in your fleet:"
    say ""
    say "    fleetctl list"
    say ""
    say "  If it is not there — an enrollment that reached a control plane holding a"
    say "  different registry, most often — add it by hand:"
    say ""
    say "    fleetctl add ${_name} --address ${_addr}"
  else
    say "  Nothing on this host can register it. Finish on your workstation:"
    say ""
    say "    fleetctl add ${_name} --address ${_addr} --insecure"
    say ""
    say "  That records the name, the address and the posture in the fleet registry,"
    say "  which is what the MCP server reads. --insecure is not a shortcut: it says"
    say "  this host authenticates nobody, and \`add\` refuses the entry if the host"
    say "  contradicts it."
  fi
  case "$(classify_address "$(host_of "$LISTEN")")" in
    loopback)
      say ""
      say "  ${LISTEN} is loopback, so only this machine can reach the agent. Run the"
      say "  MCP server here, or re-run with a listen address on a network your"
      say "  workstation is on."
      ;;
  esac
}

# ------------------------------------------------------------------- run -----

OS="$(detect_os)"
ARCH="$(detect_arch)"
SYSTEM_CONFIG_DIR="$(system_config_dir "$OS")"
detect_terminal

ask_posture
if [ "$BINARY_ONLY" = "no" ]; then
  ask_enrollment
  ask_listen
  ask_advertised
  ask_name
  ask_service
else
  # There is no config to point a service at, so there is nothing to register.
  # Said rather than silently dropped: --service yes is an instruction, and an
  # instruction this run cannot carry out should not look like one it did.
  if [ "$INSTALL_SERVICE" = "yes" ]; then
    warn "--service yes needs a configured agent to register. Nothing was configured,
so nothing is registered; pass --token or --no-mtls, or re-run on a terminal."
  fi
  INSTALL_SERVICE="no"
fi

if [ -z "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    # A system location every service account can read. `service install`
    # registers this path and never copies the binary, so where the installer
    # puts it is where the daemon is started from for the life of the host.
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi
if [ -z "$CONFIG_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    CONFIG_DIR="$SYSTEM_CONFIG_DIR"
  else
    CONFIG_DIR="$(user_config_dir)"
  fi
fi
BIN_PATH="${INSTALL_DIR}/fleet-agent"
CONFIG_PATH="${CONFIG_DIR}/agent.yaml"

# Before the download, not after it. The daemon checks this too and stays the
# authority, but through a service manager its refusal reaches an operator as a
# start that timed out — which is failure 6 in #100, three steps removed from
# the answer that caused it.
if [ -n "$NAME" ] && ! check_name "$NAME"; then
  say "error: ${NAME} is not a name this fleet can hold."
  name_rule
  exit 1
fi

if ! check_listen "$LISTEN"; then
  say "error: ${LISTEN} is not an address this agent will start on:"
  say "  ${LISTEN_REFUSAL}."
  say ""
  listen_remedy
  exit 1
fi

say ""
say "  fleet-agent, on this host:"
say ""
if [ "$VERSION" = "latest" ]; then
  # Not resolved yet, deliberately: asking the API which release is latest is a
  # network call, and a run that is about to be answered "no" at the prompt
  # below should not have made one.
  printf '    release        latest (resolved when it downloads)\n' >&2
else
  printf '    release        %s\n' "$VERSION" >&2
fi
printf '    platform       %s/%s\n' "$OS" "$ARCH" >&2
printf '    binary         %s\n' "$BIN_PATH" >&2
if [ "$BINARY_ONLY" = "yes" ]; then
  printf '    config         none: the binary and nothing else\n' >&2
else
  printf '    config         %s\n' "$CONFIG_PATH" >&2
  if [ "$MTLS" = "yes" ]; then
    printf '    authenticates  by certificate, enrolling against %s\n' "$CONTROL" >&2
    printf '    name           assigned by the control plane\n' >&2
  else
    printf '    authenticates  nobody: the network is what keeps callers out\n' >&2
    printf '    name           %s\n' "$NAME" >&2
  fi
  printf '    listens on     %s\n' "$LISTEN" >&2
  if [ -n "$ADVERTISED" ]; then
    printf '    dialled as     %s\n' "$ADVERTISED" >&2
  fi
fi
if [ "$INSTALL_SERVICE" = "yes" ]; then
  printf '    service        registered and started\n' >&2
else
  printf '    service        not registered\n' >&2
fi

if [ "$DRY_RUN" = "yes" ]; then
  say ""
  say "  Dry run: nothing was downloaded, written or registered."
  if [ "$BINARY_ONLY" = "no" ]; then
    print_next_steps
  fi
  exit 0
fi

if [ -n "$TERMINAL" ]; then
  say ""
  _proceed="$(ask "Proceed? [yes/no]" "yes" "--non-interactive")"
  case "$_proceed" in
    y|Y|yes|Yes|YES) ;;
    *) die "stopped at your request; nothing was changed." ;;
  esac
fi

VERSION="$(resolve_version)"
ARCHIVE="fleet-agent_${OS}_${ARCH}.tar.gz"
ARCHIVE_URL="${BASE_URL}/download/${VERSION}/${ARCHIVE}"
CHECKSUM_URL="${BASE_URL}/download/${VERSION}/checksums.txt"

say ""
log "fleet-agent ${VERSION} for ${OS}/${ARCH}"

TMPDIR_="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR_"; }
trap cleanup EXIT INT TERM

log "downloading ${ARCHIVE}"
fetch "$ARCHIVE_URL" "${TMPDIR_}/${ARCHIVE}" \
  || die "download failed: ${ARCHIVE_URL}"

if [ "$SKIP_CHECKSUM" = "yes" ]; then
  warn "checksum verification skipped at your request"
else
  log "verifying checksum"
  fetch "$CHECKSUM_URL" "${TMPDIR_}/checksums.txt" \
    || die "could not download checksums.txt; refusing to install unverified binary"

  expected="$(grep " ${ARCHIVE}\$" "${TMPDIR_}/checksums.txt" | awk '{print $1}' | head -n 1)"
  [ -n "$expected" ] || die "no checksum published for ${ARCHIVE}"

  actual="$(sha256_of "${TMPDIR_}/${ARCHIVE}")"
  [ -n "$actual" ] || die "no sha256 utility found; install coreutils or pass --skip-checksum"

  if [ "$expected" != "$actual" ]; then
    die "checksum mismatch for ${ARCHIVE}
  expected ${expected}
  actual   ${actual}
This means the download was corrupted or tampered with. Not installing."
  fi
  log "checksum ok"
fi

log "extracting"
tar -xzf "${TMPDIR_}/${ARCHIVE}" -C "$TMPDIR_" \
  || die "could not extract ${ARCHIVE}"
[ -f "${TMPDIR_}/fleet-agent" ] || die "archive did not contain fleet-agent"

mkdir -p "$INSTALL_DIR"
install -m 0755 "${TMPDIR_}/fleet-agent" "$BIN_PATH" 2>/dev/null \
  || { cp "${TMPDIR_}/fleet-agent" "$BIN_PATH" && chmod 0755 "$BIN_PATH"; } \
  || die "could not install to ${INSTALL_DIR} (try sudo, or --install-dir)"

log "installed ${BIN_PATH}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) warn "${INSTALL_DIR} is not on your PATH" ;;
esac

if [ "$BINARY_ONLY" = "yes" ]; then
  cat >&2 <<EOF

  Installed. Nothing else was configured: no config, no CA, no certificate, no
  service. That is what this invocation asked for -- nothing on the command line
  said which posture to configure, and there was no terminal to ask on.

  Run it again on a terminal and it will ask, offering the addresses this host
  actually has:

    curl -fsSL ${INSTALL_SCRIPT_URL} | sh

  Or say it on the command line. For a network that authenticates its own peers
  -- a tailnet, a WireGuard mesh, a tight VPC:

    curl -fsSL ${INSTALL_SCRIPT_URL} \\
      | sh -s -- --no-mtls --listen <this-host-address>:${DEFAULT_PORT}

  With mTLS off this agent authenticates nobody: anyone who can reach its port
  can run commands on this host. It refuses to serve on an address that is
  neither loopback nor private for exactly that reason. See docs/security.md.

  Otherwise, enroll against a fleet CA so both ends carry a certificate:

    curl -fsSL ${INSTALL_SCRIPT_URL} \\
      | sh -s -- --token <enrollment-token> \\
          --control <control-host:9443> \\
          --ca-fingerprint <sha256-of-the-fleet-CA>

  Mint a token on the control host with: fleetctl enroll mint
  Read its CA fingerprint with:          fleetctl ca fingerprint
EOF
  exit 0
fi

# Said whether or not roots were given, because it is true either way: the
# default config has exec on, and an agent that runs commands is not confined
# by a path check. See docs/security.md.
warn "exec is enabled, so allowed_roots is not enforced: this agent can read and"
warn "write every path its account can. Set exec.enabled: false in the config to"
warn "make --root a real jail."
if [ "$MTLS" = "yes" ]; then
  set -- enroll --token "$TOKEN" --control "$CONTROL" \
    --ca-fingerprint "$CA_FINGERPRINT" --listen "$LISTEN" --dir "$CONFIG_DIR"
  if [ -n "$NAME" ]; then
    set -- "$@" --name "$NAME"
  fi
  # Intentional word splitting for both: --address and --root are repeatable and
  # each is collected into one space-separated string.
  # shellcheck disable=SC2086
  for advertised in $ADVERTISED; do
    set -- "$@" --address "$advertised"
  done
  # shellcheck disable=SC2086
  for root in $ALLOWED_ROOTS; do
    set -- "$@" --root "$root"
  done

  log "enrolling with ${CONTROL}"
  "$BIN_PATH" "$@" || die "enrollment failed, so nothing was configured. The binary is
installed at ${BIN_PATH}; re-run the enrollment once the cause above is fixed."

  # The name the control plane assigned, which is the one the fleet knows this
  # host by. Asked of the file enrollment just wrote rather than assumed from
  # --name, because a token that reserved a name overrides what was asked for.
  NAME="$(sed -n 's/^name:[[:space:]]*//p' "$CONFIG_PATH" | head -n 1 | sed 's/^"//; s/"$//')"
else
  write_config
fi

if [ "$INSTALL_SERVICE" = "yes" ]; then
  log "registering the service"
  # Not swallowed. Until #100 a registration that failed was a warning and the
  # installer went on to report success, which left the operator with a host
  # they believed had joined the fleet and a service that had never been
  # written. `service install` refuses for reasons that are all worth reading —
  # no elevation, a binary the service account cannot read, an account that
  # does not exist — and each of them is fixed and re-run, not ignored.
  "$BIN_PATH" service install --config "$CONFIG_PATH" \
    || die "registering the service failed, so this host is not running the agent.
The binary and the config are in place: fix the cause above and run
  ${BIN_PATH} service install --config ${CONFIG_PATH}"

  "$BIN_PATH" service start \
    || die "the service was registered and would not start.
Read \`${BIN_PATH} service status\` for what the daemon recorded, fix it, and run
  ${BIN_PATH} service start"

  verify_running
  say ""
  say "  Installed, configured, running."
else
  say ""
  say "  Installed and configured. Nothing is running: no service was registered."
  say ""
  say "  Register and start it with:"
  say ""
  if [ "$(id -u)" -eq 0 ]; then
    say "    ${BIN_PATH} service install --config ${CONFIG_PATH}"
    say "    ${BIN_PATH} service start"
  else
    say "    sudo ${BIN_PATH} service install --config ${CONFIG_PATH}"
    say "    sudo ${BIN_PATH} service start"
  fi
fi

print_next_steps
