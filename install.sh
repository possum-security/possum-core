#!/usr/bin/env sh
# Possum Core Release Installer
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/possum-security/possum-core/main/install.sh | sh
#   POSSUM_VERSION=v0.1.0 INSTALL_DIR=/usr/local/bin ./install.sh

set -eu

REPO="possum-security/possum-core"
BINARY="possum"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

log_info() {
  printf "==> %s\n" "$1"
}

log_err() {
  printf "Error: %s\n" "$1" >&2
  exit 1
}

detect_os() {
  os_name="$(uname -s)"
  case "$os_name" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       log_err "Unsupported operating system: ${os_name} (only Linux and macOS are supported by install.sh)" ;;
  esac
}

detect_arch() {
  arch_name="$(uname -m)"
  case "$arch_name" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)             log_err "Unsupported CPU architecture: ${arch_name} (only amd64 and arm64 are supported)" ;;
  esac
}

verify_sha256() {
  archive_file="$1"
  checksums_file="$2"
  archive_name="$(basename "$archive_file")"

  expected_hash="$(grep -E "[[:space:]]${archive_name}\$" "$checksums_file" | awk '{print $1}' || true)"
  if [ -z "$expected_hash" ]; then
    log_err "Checksum for ${archive_name} not found in checksums.txt"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual_hash="$(sha256sum "$archive_file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual_hash="$(shasum -a 256 "$archive_file" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    actual_hash="$(openssl dgst -sha256 "$archive_file" | awk '{print $NF}')"
  else
    log_err "No SHA-256 verification tool found (requires sha256sum, shasum, or openssl)"
  fi

  if [ "$expected_hash" != "$actual_hash" ]; then
    log_err "SHA-256 checksum mismatch for ${archive_name}! Expected ${expected_hash}, got ${actual_hash}"
  fi
  log_info "Verified SHA-256 checksum (${actual_hash})"
}

main() {
  if ! command -v curl >/dev/null 2>&1; then
    log_err "curl is required to download Possum releases"
  fi
  if ! command -v tar >/dev/null 2>&1; then
    log_err "tar is required to extract Possum releases"
  fi

  os="$(detect_os)"
  arch="$(detect_arch)"

  version="${POSSUM_VERSION:-}"
  if [ -z "$version" ]; then
    log_info "Resolving latest release version from GitHub..."
    version="$(curl -sSfL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')"
    if [ -z "$version" ]; then
      log_err "Could not determine latest version from GitHub API. Set POSSUM_VERSION explicitly."
    fi
  fi

  version_num="${version#v}"
  archive_name="${BINARY}_${version_num}_${os}_${arch}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${version}"

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  log_info "Downloading ${archive_name} (${version})..."
  curl -sSfL "${base_url}/${archive_name}" -o "${tmp_dir}/${archive_name}"
  curl -sSfL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"

  verify_sha256 "${tmp_dir}/${archive_name}" "${tmp_dir}/checksums.txt"

  tar -xzf "${tmp_dir}/${archive_name}" -C "$tmp_dir"
  if [ ! -f "${tmp_dir}/${BINARY}" ]; then
    log_err "Extracted archive did not contain ${BINARY} binary"
  fi
  chmod 0755 "${tmp_dir}/${BINARY}"

  if [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
  fi

  if [ -w "$INSTALL_DIR" ]; then
    mv "${tmp_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  else
    log_info "Installing to ${INSTALL_DIR} (requires elevated permissions)..."
    sudo mv "${tmp_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  fi

  log_info "Installed ${BINARY} ${version} to ${INSTALL_DIR}/${BINARY}"
  "${INSTALL_DIR}/${BINARY}" version || true
}

main "$@"
