#!/usr/bin/env bash
# Pinned elan (the Lean toolchain manager) and Lean toolchain for the formal model's CI job: each release archive by
# version and SHA-256 digest, never the moving "latest" that elan-init.sh fetches nor an archive elan downloads
# unchecked. The toolchain is the one of formal/lean-toolchain, registered with `elan toolchain link` under its own
# name, so `lake` finds it installed and elan downloads nothing. A runner that already has elan, or that toolchain,
# keeps it.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version=4.2.4
lean_version=4.35.0
toolchain="leanprover/lean4:v${lean_version}"
[ "$(cat "$root/formal/lean-toolchain")" = "$toolchain" ] \
  || { echo "formal/lean-toolchain is not $toolchain: pin the new version and its digests here" >&2; exit 1; }
home="${ELAN_HOME:-$HOME/.elan}"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=x86_64-unknown-linux-gnu; lean_platform=linux ;;
  Darwin-arm64) target=aarch64-apple-darwin; lean_platform=darwin_aarch64 ;;
  *) echo 'Unsupported elan runner platform' >&2; exit 1 ;;
esac
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT
# url, sha256, file: downloads into the temporary directory and stops unless the digest matches
fetch() {
  [[ $2 =~ ^[0-9a-f]{64}$ ]] || { echo "No SHA-256 pinned for $3: refusing to download it unchecked" >&2; exit 1; }
  (cd "$task_tmp" && curl -sSfL -o "$3" --retry 6 --retry-delay 15 --retry-all-errors --max-time 600 "$1" \
    && printf '%s  %s\n' "$2" "$3" | shasum -a 256 -c -)
}
if [ ! -x "$home/bin/elan" ]; then
  # Digests pinned from https://github.com/leanprover/elan/releases/tag/v4.2.4 (asset digests)
  case "$target" in
    x86_64-unknown-linux-gnu) expected=42b94d4244e8353142c456ec0e4ca6528fd898a6c604d4059f494e706e431f63 ;;
    aarch64-apple-darwin) expected=7ad829861392c718dfebde3a83b5c8508df47be02af68894b094b0b3952616e5 ;;
  esac
  archive="elan-${target}.tar.gz"
  fetch "https://github.com/leanprover/elan/releases/download/v${version}/${archive}" "$expected" "$archive"
  tar -xzf "$task_tmp/$archive" -C "$task_tmp" elan-init
  "$task_tmp/elan-init" -y --default-toolchain none --no-modify-path
fi
if ! "$home/bin/elan" toolchain list | cut -d " " -f 1 | grep -qxF "$toolchain"; then
  # Digests of the official release assets, https://github.com/leanprover/lean4/releases/tag/v4.35.0
  # (the "digest" GitHub records for each release asset, read from the releases API)
  case "$target" in
    x86_64-unknown-linux-gnu) lean_expected=7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d ;;
    aarch64-apple-darwin) lean_expected=c0c6f34f35ba1dcc5c4a5fd106fefab9eb5e8469712624dd2c868d51b63177c2 ;;
  esac
  lean_dir="lean-${lean_version}-${lean_platform}"
  fetch "https://github.com/leanprover/lean4/releases/download/v${lean_version}/${lean_dir}.tar.zst" "$lean_expected" "${lean_dir}.tar.zst"
  mkdir -p "$home/pinned"
  zstd -dc "$task_tmp/${lean_dir}.tar.zst" | tar -xf - -C "$home/pinned"
  "$home/bin/elan" toolchain link "$toolchain" "$home/pinned/$lean_dir"
fi
if [ -n "${GITHUB_PATH:-}" ]; then echo "$home/bin" >> "$GITHUB_PATH"; fi
"$home/bin/elan" --version
