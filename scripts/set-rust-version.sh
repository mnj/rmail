#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <semver>" >&2
  exit 2
fi

VERSION="$1"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "invalid semver: ${VERSION}" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

while IFS= read -r manifest; do
  RMAIL_VERSION="${VERSION}" perl -0pi -e '
    my $version = $ENV{"RMAIL_VERSION"};
    s/(\[package\][^\[]*?\nversion\s*=\s*")[^"]+(")/$1$version$2/s
      or die "missing [package] version in $ARGV\n";
  ' "${manifest}"
  echo "set ${manifest#${ROOT_DIR}/} to ${VERSION}"
done < <(find "${ROOT_DIR}/crates" -mindepth 2 -maxdepth 2 -name Cargo.toml | sort)
