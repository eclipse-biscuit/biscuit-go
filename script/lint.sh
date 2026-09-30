#!/usr/bin/env bash
#
# Runs golangci-lint at a pinned version so local runs and CI agree. The
# binary is downloaded into build/bin and its checksum verified against the
# release's published checksums file.

set -euo pipefail

GOLANGCI_LINT_VERSION="2.14.0"
GOLANGCI_LINT_CHECKSUMS_SHA256="7b4eeb888873ac45ec58a640c3243c43a3540e097f6c4410efd2bdb306340023"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT}/build/bin"
BIN="${BIN_DIR}/golangci-lint-${GOLANGCI_LINT_VERSION}"

install() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64 | arm64) arch="arm64" ;;
        *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac

    local name="golangci-lint-${GOLANGCI_LINT_VERSION}-${os}-${arch}"
    local base="https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}"
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "${tmp}"' EXIT

    curl -sSfL -o "${tmp}/checksums.txt" "${base}/golangci-lint-${GOLANGCI_LINT_VERSION}-checksums.txt"
    echo "${GOLANGCI_LINT_CHECKSUMS_SHA256}  ${tmp}/checksums.txt" | sha256sum -c - >/dev/null

    curl -sSfL -o "${tmp}/${name}.tar.gz" "${base}/${name}.tar.gz"
    (cd "${tmp}" && grep " ${name}.tar.gz\$" checksums.txt | sha256sum -c - >/dev/null)

    tar -xzf "${tmp}/${name}.tar.gz" -C "${tmp}"
    mkdir -p "${BIN_DIR}"
    mv "${tmp}/${name}/golangci-lint" "${BIN}"
}

if [ ! -x "${BIN}" ]; then
    install
fi

cd "${ROOT}"
exec "${BIN}" run "$@"
