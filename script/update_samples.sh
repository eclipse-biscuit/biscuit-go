#!/usr/bin/env bash

set -ueo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
# Commit of https://github.com/eclipse-biscuit/biscuit the samples are synced from.
SAMPLES_REV="b3d3fe2d744ea8ee964ab0eba96dbc8c9bde1639"

TMP_DIR="${DIR}/../build"
SAMPLES_DIR="${DIR}/../samples"

cleanup() {
    rm -rf "${DIR}/../build/biscuit_spec"
}

trap "cleanup" ERR

# Clone and sync sample files from spec repo
if [ -d "${TMP_DIR}/biscuit_spec" ]; then
    cleanup
fi

mkdir -p "${TMP_DIR}"
git -C "${TMP_DIR}" clone https://github.com/eclipse-biscuit/biscuit.git biscuit_spec
git -C "${TMP_DIR}/biscuit_spec" checkout "${SAMPLES_REV}"
rsync -prav --delete-before "${TMP_DIR}/biscuit_spec/samples/current/" "${SAMPLES_DIR}/data/current"

cleanup
