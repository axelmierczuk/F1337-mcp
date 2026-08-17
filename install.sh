#!/bin/sh
# fleet-agent installer.
#
#   curl -fsSL https://raw.githubusercontent.com/axelmierczuk/fleet-mcp/main/install.sh \
#     | sh -s -- --token <enrollment-token> --control <control-host:9443> \
#         --ca-fingerprint <sha256-of-the-fleet-CA> --root /path/to/workspace
#
# Downloads the release binary for this platform, verifies its SHA-256 against
# the release checksum file, installs it, and optionally enrolls the host and
# registers a system service.
#
# Piping a script from the network into a shell is trust-on-first-use no matter
# how careful the script is. This one at least refuses to install an artifact
# whose checksum does not match the one published alongside it, and it always
# pins the control-plane CA — enrollment will not run without a fingerprint.

set -eu

REPO="axelmierczuk/fleet-mcp"
BASE_URL="https://github.com/${REPO}/releases"
API_URL="https://api.github.com/repos/${REPO}/releases"

VERSION="latest"
INSTALL_DIR=""
TOKEN=""
CONTROL=""
LISTEN="0.0.0.0:8722"
NAME=""
CA_FINGERPRINT=""
INSTALL_SERVICE="auto"
ALLOWED_ROOTS=""
SKIP_CHECKSUM="no"

log()  { printf '  %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
Usage: install.sh [options]

Options:
  --token <token>          Enrollment token from `fleetctl enroll mint`.
                           When set, the host enrolls after installation, and
                           --control and --ca-fingerprint become required.
  --control <host:port>    Control-plane enrollment endpoint.
  --ca-fingerprint <hex>   SHA-256 fingerprint of the control-plane CA to pin,
                           from `fleetctl ca fingerprint`. Required with
                           --token: enrollment refuses to run unpinned.
  --listen <addr:port>     Address the agent serves gRPC on (default 0.0.0.0:8722).
  --name <name>            Sandbox name to request. Only for a token that
                           reserved none; the control plane refuses a name
                           other than the one its token authorizes.
  --root <path>            Filesystem root the agent may access. Repeatable.
                           Enforced only when exec.enabled is false in the
                           config: a caller that can run commands reaches any
                           path without going through FileService.
  --version <vX.Y.Z>       Release to install (default: latest).
  --install-dir <path>     Install prefix (default: /usr/local/bin, or
                           ~/.local/bin for an unprivileged install).
  --service <yes|no|auto>  Register a system service (default: auto, meaning
                           yes when running as root).
  --skip-checksum          Skip checksum verification. Do not use this.
  -h, --help               Show this help.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --token)           TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --control)         CONTROL="${2:?--control needs a value}"; shift 2 ;;
    --ca-fingerprint)  CA_FINGERPRINT="${2:?--ca-fingerprint needs a value}"; shift 2 ;;
    --listen)          LISTEN="${2:?--listen needs a value}"; shift 2 ;;
    --name)            NAME="${2:?--name needs a value}"; shift 2 ;;
    --root)            ALLOWED_ROOTS="${ALLOWED_ROOTS} ${2:?--root needs a value}"; shift 2 ;;
    --version)         VERSION="${2:?--version needs a value}"; shift 2 ;;
    --install-dir)     INSTALL_DIR="${2:?--install-dir needs a value}"; shift 2 ;;
    --service)         INSTALL_SERVICE="${2:?--service needs a value}"; shift 2 ;;
    --skip-checksum)   SKIP_CHECKSUM="yes"; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "unknown option: $1 (try --help)" ;;
  esac
done

# Checked here rather than at the enroll step, so an invocation that cannot
# possibly enroll costs nothing. Discovering it after the download leaves a
# binary installed on a host that never joined the fleet, which is the worst of
# both outcomes.
if [ -n "$TOKEN" ]; then
  [ -n "$CONTROL" ] || die "--token requires --control <host:port>"
  if [ -z "$CA_FINGERPRINT" ]; then
    die "--token requires --ca-fingerprint <hex>

\`fleet-agent enroll\` refuses to run unpinned. Without the fingerprint,
anything that can answer on the network collects the token, and the token is
the only thing between an attacker and a fleet identity.

Get it from the control host with: fleetctl ca fingerprint"
  fi
fi

# ---------------------------------------------------------------- platform ---

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

# ------------------------------------------------------------------ fetch ----

have() { command -v "$1" >/dev/null 2>&1; }

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

# --------------------------------------------------------------- install -----

OS="$(detect_os)"
ARCH="$(detect_arch)"
VERSION="$(resolve_version)"

if [ -z "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

if [ "$INSTALL_SERVICE" = "auto" ]; then
  if [ "$(id -u)" -eq 0 ]; then INSTALL_SERVICE="yes"; else INSTALL_SERVICE="no"; fi
fi

ARCHIVE="fleet-agent_${OS}_${ARCH}.tar.gz"
ARCHIVE_URL="${BASE_URL}/download/${VERSION}/${ARCHIVE}"
CHECKSUM_URL="${BASE_URL}/download/${VERSION}/checksums.txt"

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
install -m 0755 "${TMPDIR_}/fleet-agent" "${INSTALL_DIR}/fleet-agent" 2>/dev/null \
  || { cp "${TMPDIR_}/fleet-agent" "${INSTALL_DIR}/fleet-agent" && chmod 0755 "${INSTALL_DIR}/fleet-agent"; } \
  || die "could not install to ${INSTALL_DIR} (try sudo, or --install-dir)"

log "installed ${INSTALL_DIR}/fleet-agent"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) warn "${INSTALL_DIR} is not on your PATH" ;;
esac

# --------------------------------------------------------------- enroll ------

if [ -n "$TOKEN" ]; then
  set -- enroll --token "$TOKEN" --control "$CONTROL" \
    --ca-fingerprint "$CA_FINGERPRINT" --listen "$LISTEN"
  if [ -n "$NAME" ]; then
    set -- "$@" --name "$NAME"
  fi
  # Intentional word splitting: --root is repeatable and roots are collected
  # into a single space-separated string above.
  # shellcheck disable=SC2086
  for root in $ALLOWED_ROOTS; do
    set -- "$@" --root "$root"
  done

  # Said whether or not roots were given, because it is true either way: the
  # default config has exec on, and an agent that runs commands is not confined
  # by a path check. See docs/security.md.
  warn "exec is enabled, so allowed_roots is not enforced: this agent can read and"
  warn "write every path its account can. Set exec.enabled: false in the config to"
  warn "make --root a real jail."

  log "enrolling with ${CONTROL}"
  "${INSTALL_DIR}/fleet-agent" "$@" || die "enrollment failed"

  if [ "$INSTALL_SERVICE" = "yes" ]; then
    log "registering system service"
    "${INSTALL_DIR}/fleet-agent" service install \
      || warn "service registration failed; run 'fleet-agent service install' manually"
    "${INSTALL_DIR}/fleet-agent" service start \
      || warn "service did not start; check 'fleet-agent service status'"
  fi

  log "done. This host should now appear in sandbox_list."
else
  cat >&2 <<EOF

  Installed, but not enrolled. To join a fleet:

    ${INSTALL_DIR}/fleet-agent enroll \\
      --token <enrollment-token> \\
      --control <control-host:9443> \\
      --ca-fingerprint <sha256-of-the-fleet-CA> \\
      --root /path/to/workspace

  Mint a token on the control host with: fleetctl enroll mint
  Read its CA fingerprint with:          fleetctl ca fingerprint
EOF
fi
