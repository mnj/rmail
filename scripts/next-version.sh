#!/usr/bin/env bash
# Print the next release version (without a leading "v").
#
# usage: next-version.sh <auto|patch|minor|major> [pr-title]
#
# The base is the highest stable vX.Y.Z tag. The workspace version in
# crates/common/Cargo.toml acts as a floor: bumping it by hand (for example to
# 1.0.0) makes the next release use that version as-is. With no tags at all,
# the Cargo version is released unchanged.
#
# "auto" picks the bump from a Conventional Commits style PR title:
# "feat!:" / "fix(scope)!:" -> major, "feat:" -> minor, anything else -> patch.
set -euo pipefail

BUMP="${1:-auto}"
TITLE="${2:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEMVER_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

case "${BUMP}" in
  auto | patch | minor | major) ;;
  *)
    echo "unknown bump: ${BUMP}" >&2
    exit 2
    ;;
esac

cargo_version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${ROOT_DIR}/crates/common/Cargo.toml" | head -n1)"
if [[ ! "${cargo_version}" =~ ${SEMVER_RE} ]]; then
  echo "unexpected workspace version: '${cargo_version}'" >&2
  exit 1
fi

latest_tag="$(git -C "${ROOT_DIR}" tag -l 'v[0-9]*' | sed 's/^v//' | grep -E "${SEMVER_RE}" | sort -V | tail -n1 || true)"

if [[ "${BUMP}" == "auto" ]]; then
  if [[ "${TITLE}" =~ ^[a-zA-Z]+(\([^\)]*\))?!: ]] || [[ "${TITLE}" == *"BREAKING CHANGE"* ]]; then
    BUMP=major
  elif [[ "${TITLE}" =~ ^feat(\([^\)]*\))?: ]]; then
    BUMP=minor
  else
    BUMP=patch
  fi
fi

if [[ -z "${latest_tag}" ]]; then
  echo "${cargo_version}"
  exit 0
fi

# A hand-bumped Cargo version ahead of the last tag wins.
if [[ "${cargo_version}" != "${latest_tag}" ]] &&
   [[ "$(printf '%s\n%s\n' "${cargo_version}" "${latest_tag}" | sort -V | tail -n1)" == "${cargo_version}" ]]; then
  echo "${cargo_version}"
  exit 0
fi

IFS=. read -r major minor patch <<<"${latest_tag}"
case "${BUMP}" in
  major) echo "$((major + 1)).0.0" ;;
  minor) echo "${major}.$((minor + 1)).0" ;;
  patch) echo "${major}.${minor}.$((patch + 1))" ;;
esac
