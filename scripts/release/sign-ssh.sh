#!/usr/bin/env bash
# Release signing hook (owner decision 2026-11-17: an SSH ed25519 key on the release runner). pack.sh runs it as
# `sign-ssh.sh <dir>/SHA256SUMS`; it writes SHA256SUMS.sig (ssh-keygen -Y sign, namespace "file") and checks it against
# the committed allowed_signers before the release goes out. The private key is encrypted and stays on the runner
# (RELEASE_SSH_KEY, default below). Its passphrase comes from RELEASE_SSH_KEY_PASSPHRASE (the release job passes the
# repository secret, since a headless runner has no usable Keychain) or else from the macOS login Keychain.
set -euo pipefail
sums="${1:?Usage: sign-ssh.sh <SHA256SUMS>}"
key="${RELEASE_SSH_KEY:-$HOME/.config/qadamar/release-signing/release_ed25519}"
signers="${RELEASE_ALLOWED_SIGNERS:-$(cd "$(dirname "$0")" && pwd)/allowed_signers}"
[ -r "$key" ] || { echo "Release signing key not readable: $key" >&2; exit 1; }
askpass=$(mktemp); trap 'rm -f "$askpass"' EXIT
if [ -n "${RELEASE_SSH_KEY_PASSPHRASE:-}" ]; then
  printf '#!/bin/sh\nprintf "%%s\\n" "$RELEASE_SSH_KEY_PASSPHRASE"\n' > "$askpass" # the value stays in the environment, never in the file
else
  printf '#!/bin/sh\nexec security find-generic-password -w -s qadamar-release-signing\n' > "$askpass"
fi
chmod 700 "$askpass"
rm -f "$sums.sig"
SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none ssh-keygen -q -Y sign -f "$key" -n file "$sums" < /dev/null
ssh-keygen -q -Y verify -f "$signers" -I release@qadamar -n file -s "$sums.sig" < "$sums" > /dev/null
echo "Signed $sums -> $sums.sig"
