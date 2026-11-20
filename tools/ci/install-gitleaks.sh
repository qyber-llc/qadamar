#!/usr/bin/env bash
# Pinned Gitleaks (version and SHA-256 digests).
set -euo pipefail
version=8.30.1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux_x64 ;;
  Darwin-arm64) platform=darwin_arm64 ;;
  *) echo 'Unsupported Gitleaks runner platform' >&2; exit 1 ;;
esac
archive="gitleaks_${version}_${platform}.tar.gz"
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT
cd "$task_tmp"
base="https://github.com/gitleaks/gitleaks/releases/download/v${version}"
curl -sSfLO --retry 6 --retry-delay 15 --retry-all-errors --max-time 120 "$base/$archive"
# Digests pinned from https://github.com/gitleaks/gitleaks/releases/expanded_assets/v8.30.1
case "$platform" in
  linux_x64) expected=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;;
  darwin_arm64) expected=b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5 ;;
esac
[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || { echo 'Missing or invalid Gitleaks checksum'; exit 1; }
# shasum ships on both macOS and hosted Ubuntu.
printf '%s  %s\n' "$expected" "$archive" | shasum -a 256 -c -
tar -xzf "$archive" gitleaks
bin="${GITHUB_WORKSPACE:-$PWD}/.ci-bin"
mkdir -p "$bin"
install -m 0755 gitleaks "$bin/gitleaks"
if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >> "$GITHUB_PATH"; fi
