#!/usr/bin/env bash
set -euo pipefail

node_version="${1:?Node.js version is required}"
runner_temp="${RUNNER_TEMP:-$(mktemp -d)}"

case "$(uname -s)" in
  Darwin)
    platform="darwin"
    archive_ext="tar.gz"
    ;;
  Linux)
    platform="linux"
    archive_ext="tar.gz"
    ;;
  *)
    echo "Unsupported CI platform: $(uname -s)" >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) architecture="x64" ;;
  arm64 | aarch64) architecture="arm64" ;;
  *)
    echo "Unsupported CI architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

archive="node-v${node_version}-${platform}-${architecture}.${archive_ext}"
download_base="https://nodejs.org/dist/v${node_version}"
install_root="${runner_temp}/citrx-node-${node_version}"
node_root="${install_root}/node-v${node_version}-${platform}-${architecture}"

mkdir -p "$install_root"
curl --fail --silent --show-error --location "${download_base}/${archive}" --output "${install_root}/${archive}"
curl --fail --silent --show-error --location "${download_base}/SHASUMS256.txt" --output "${install_root}/SHASUMS256.txt"

expected_checksum="$(awk -v archive="$archive" '$2 == archive { print $1 }' "${install_root}/SHASUMS256.txt")"
expected_checksum="${expected_checksum//$'\r'/}"
if [[ -z "$expected_checksum" ]]; then
  echo "Missing checksum for ${archive}" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_checksum="$(sha256sum "${install_root}/${archive}" | awk '{ print $1 }')"
else
  actual_checksum="$(shasum -a 256 "${install_root}/${archive}" | awk '{ print $1 }')"
fi
actual_checksum="${actual_checksum//$'\r'/}"

if [[ "$actual_checksum" != "$expected_checksum" ]]; then
  echo "Checksum mismatch for ${archive}" >&2
  exit 1
fi

tar -xf "${install_root}/${archive}" -C "$install_root"

node_bin="${node_root}/bin"

export PATH="${node_bin}:${PATH}"
node --version
npm --version
npm install --global pnpm@11.1.0
pnpm --version
