#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

pack_dir="$(mktemp -d "${TMPDIR:-/tmp}/citrx-pack.XXXXXX")"
install_dir="$(mktemp -d "${TMPDIR:-/tmp}/citrx-install.XXXXXX")"

cleanup() {
  rm -rf "$pack_dir" "$install_dir"
}
trap cleanup EXIT

pnpm pack --pack-destination "$pack_dir"
tarball="$(find "$pack_dir" -name '*citrx-*.tgz' | head -n 1)"
if [[ -z "$tarball" ]]; then
  echo "package smoke: no tarball produced" >&2
  exit 1
fi

contents="$(tar -tzf "$tarball")"
echo "$contents" | grep -qx 'package/dist/cli.js'
echo "$contents" | grep -qx 'package/README.md'
echo "$contents" | grep -qx 'package/README_ES.md'
echo "$contents" | grep -qx 'package/LICENSE'
echo "$contents" | grep -qx 'package/package.json'

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  path="${path%/}"
  case "$path" in
    package | package/package.json | package/README.md | package/README_ES.md | package/LICENSE | package/dist | package/dist/*) ;;
    *)
      echo "package smoke: unexpected path $path" >&2
      exit 1
      ;;
  esac
done <<<"$contents"

(
  cd "$install_dir"
  npm init -y >/dev/null
  npm install --omit=dev "$tarball" >/dev/null
  ./node_modules/.bin/citrx --version
)

if find "$root" -maxdepth 1 -name '*.tgz' | grep -q .; then
  echo "package smoke: leftover tarball in repo root" >&2
  exit 1
fi
