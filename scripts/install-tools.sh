#!/usr/bin/env bash
# Install the scanners the Security Gate uses, at PINNED versions, verified by checksum.
# (The scan pipeline itself is a supply-chain target: never "latest", never unverified.)
#
# Usage:  ./scripts/install-tools.sh
# Installs into $VIRTUAL_ENV/bin if a venv is active, otherwise ./.tools/bin.
# To upgrade a tool: change its version AND checksums below in one reviewed commit.
set -euo pipefail

GITLEAKS_VERSION="8.30.1"

gitleaks_sha256() {  # a function, not an associative array: macOS ships bash 3.2
  case "$1" in
    darwin_arm64) echo "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5" ;;
    darwin_x64)   echo "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709" ;;
    linux_arm64)  echo "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" ;;
    linux_x64)    echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" ;;
    *) echo "unsupported platform: $1" >&2; exit 1 ;;
  esac
}

if [[ -n "${VIRTUAL_ENV:-}" ]]; then TOOLS_DIR="$VIRTUAL_ENV/bin"; else TOOLS_DIR="$(pwd)/.tools/bin"; fi
mkdir -p "$TOOLS_DIR"

platform() {
  local os arch
  case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
  case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=x64 ;; *) echo "unsupported CPU" >&2; exit 1 ;; esac
  echo "${os}_${arch}"
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

install_gitleaks() {
  local p tarball tmp
  p="$(platform)"
  tarball="gitleaks_${GITLEAKS_VERSION}_${p}.tar.gz"
  tmp="$(mktemp -d)"
  echo "==> gitleaks ${GITLEAKS_VERSION} (${p})"
  curl -fsSL -o "$tmp/$tarball" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${tarball}"
  if [[ "$(sha256_of "$tmp/$tarball")" != "$(gitleaks_sha256 "$p")" ]]; then
    echo "CHECKSUM MISMATCH for $tarball - refusing to install" >&2; rm -rf "$tmp"; exit 1
  fi
  tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks
  install -m 0755 "$tmp/gitleaks" "$TOOLS_DIR/gitleaks"
  rm -rf "$tmp"
  echo "    installed $TOOLS_DIR/gitleaks (checksum verified)"
}

install_gitleaks
echo "Done. Tools are in: $TOOLS_DIR"
