#!/usr/bin/env bash
#
# Static checks that must pass before a change is merged. Every check runs even
# if an earlier one fails so that a single run reports everything.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

failed=0

check() {
    local name="$1"
    shift
    echo "==> ${name}"
    if ! "$@"; then
        echo "FAIL: ${name}" >&2
        failed=1
    fi
}

verify_gofmt() {
    local unformatted
    unformatted=$(gofmt -s -l . | grep -v '^build/') || true
    if [ -n "${unformatted}" ]; then
        echo "files are not gofmt'd, run 'gofmt -s -w' on:" >&2
        echo "${unformatted}" >&2
        return 1
    fi
}

verify_vet() {
    # structtag is disabled because participle grammar tags are not key:"value"
    # pairs, see parser/grammar.go.
    go vet -structtag=false ./...
}

verify_gomod() {
    # Prints the changes `go mod tidy` would make and fails if there are any.
    go mod tidy -diff
}

check "gofmt" verify_gofmt
check "go vet" verify_vet
check "go mod tidy" verify_gomod

exit "${failed}"
