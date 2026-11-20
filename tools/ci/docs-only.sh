#!/usr/bin/env bash
# Markdown/docs-only changes skip the gate, except README (its generated measurements must be checked), docs/spec
# (the schema and formal-model specification the tests read), and the generated configuration table and the
# changelog (the gate checks both).
# Manual runs, first pushes and unreadable diffs run everything (fail closed).
set -euo pipefail
out="${GITHUB_OUTPUT:-/dev/stdout}"
zero=0000000000000000000000000000000000000000
if [ -z "${BASE_SHA:-}" ] || [ "${BASE_SHA}" = "$zero" ] || [ -z "${HEAD_SHA:-}" ]; then echo docs_only=false >> "$out"; exit 0; fi
base=$(git merge-base "$BASE_SHA" "$HEAD_SHA" 2>/dev/null) || { echo docs_only=false >> "$out"; exit 0; }
changed=$(git diff --name-only --no-renames "$base" "$HEAD_SHA") || { echo docs_only=false >> "$out"; exit 0; }
if [ -z "$changed" ]; then echo docs_only=false >> "$out"; exit 0; fi
while IFS= read -r path; do
  case "$path" in
    README.md) echo docs_only=false >> "$out"; exit 0 ;;
    docs/spec/*) echo docs_only=false >> "$out"; exit 0 ;;
    docs/CONFIGURATION.md|CHANGELOG.md) echo docs_only=false >> "$out"; exit 0 ;;
    docs/*|*.md) ;;
    *) echo docs_only=false >> "$out"; exit 0 ;;
  esac
done <<< "$changed"
echo docs_only=true >> "$out"
