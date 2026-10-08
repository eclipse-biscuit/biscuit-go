#!/usr/bin/env bash
#
# Checks for incompatible Go API changes against a base ref or directory using
# golang.org/x/exp/cmd/apidiff.

set -o errexit
set -o nounset
set -o pipefail

function usage {
  local script
  script="$(basename "$0")"

  echo >&2 "Usage: ${script} [-r <branch|tag> | -d <dir>]

This script should be run at the root of a module.

-r <branch|tag>
  Compare the exported API of the local working copy with the
  exported API of the local repo at the specified branch or tag.

-d <dir>
  Compare the exported API of the local working copy with the
  exported API of the specified directory, which should point
  to the root of a different version of the same module.

Examples:
  ${script} -r main
  ${script} -r v2.2.0
  ${script} -d /path/to/historical/version
"
  exit 1
}

ref=""
dir=""
while getopts r:d: o
do case "$o" in
  r)    ref="$OPTARG";;
  d)    dir="$OPTARG";;
  [?])  usage;;
  esac
done

# If REF and DIR are empty, print usage and error
if [[ -z "${ref}" && -z "${dir}" ]]; then
  usage
fi
# If REF and DIR are both set, print usage and error
if [[ -n "${ref}" && -n "${dir}" ]]; then
  usage
fi

export PATH="$(go env GOPATH)/bin:${PATH}"
if ! which apidiff > /dev/null; then
  echo "Installing golang.org/x/exp/cmd/apidiff..."
  pushd "${TMPDIR:-/tmp}" > /dev/null
    go install golang.org/x/exp/cmd/apidiff@latest
  popd > /dev/null
fi

output=$(mktemp -d -t "apidiff.output.XXXX")
cleanup_output () { rm -fr "${output}"; }
trap cleanup_output EXIT

# If ref is set, clone . to temp dir at $ref, and set $dir to the temp dir
clone=""
base="${dir}"
if [[ -n "${ref}" ]]; then
  base="${ref}"
  clone=$(mktemp -d -t "apidiff.clone.XXXX")
  cleanup_clone_and_output () { rm -fr "${clone}"; cleanup_output; }
  trap cleanup_clone_and_output EXIT
  git clone . -q --no-tags -b "${ref}" "${clone}"
  dir="${clone}"
fi

pushd "${dir}" >/dev/null
  echo "Inspecting API of ${base}..."
  go list ./... > "${output}/old_packages.txt"
  for pkg in $(cat "${output}/old_packages.txt"); do
    mkdir -p "${output}/${pkg}"
    apidiff -w "${output}/${pkg}/apidiff.output" "${pkg}"
  done
popd >/dev/null

retval=0

echo "Comparing with ${base}..."
for pkg in $(go list ./...); do
  # New packages are ok
  if [ ! -f "${output}/${pkg}/apidiff.output" ]; then
    continue
  fi

  # Check for incompatible changes to previous packages
  incompatible=$(apidiff -incompatible "${output}/${pkg}/apidiff.output" "${pkg}")
  if [[ -n "${incompatible}" ]]; then
    echo >&2 "FAIL: ${pkg} contains incompatible changes:
${incompatible}
"
    retval=1
  fi
done

# Check for removed packages
removed=$(comm -23 "${output}/old_packages.txt" <(go list ./...))
if [[ -n "${removed}" ]]; then
  echo >&2 "FAIL: removed packages:
${removed}
"
  retval=1
fi

exit $retval
