#!/usr/bin/env bash
# Versioned, reproducible tarball of the deployable server, its CycloneDX SBOM and SHA256SUMS (docs/RELEASE.md).
#   bash scripts/release/pack.sh [vX.Y.Z]     needs pnpm install done; writes dist/release/X.Y.Z/ (OUT_DIR overrides)
# The tag, when given, must equal the server's package version. A dirty work tree is refused (ALLOW_DIRTY=1 for a local
# trial; BUILD-INFO then says dirty). RELEASE_SIGNING_HOOK, when set, is run on SHA256SUMS (owner decision, unset = unsigned).
set -euo pipefail
cd "$(dirname "$0")/../.."
export LC_ALL=C TZ=UTC COPYFILE_DISABLE=1

version=$(node -p 'require("./packages/pdp-http/package.json").version')
if [ -n "${1:-}" ] && [ "$1" != "v$version" ]; then echo "Tag $1 does not match the server version v$version" >&2; exit 1; fi
dirty=false
if [ -n "$(git status --porcelain)" ]; then
  [ "${ALLOW_DIRTY:-}" = 1 ] || { echo 'Work tree has uncommitted changes: commit them or set ALLOW_DIRTY=1 for a trial' >&2; git status --porcelain | head -20 >&2; exit 1; }
  dirty=true
fi
commit=$(git rev-parse HEAD)
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
[[ "$epoch" =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be a Unix time in seconds' >&2; exit 1; }
export SOURCE_DATE_EPOCH=$epoch
name="qadamar-$version"
out=${OUT_DIR:-dist/release/$version}
mkdir -p "$out"
for f in "$name.tar.gz" "$name.cdx.json" SHA256SUMS; do
  [ ! -e "$out/$f" ] || { echo "Refusing to overwrite $out/$f" >&2; exit 1; }
done

pnpm --filter @product/admin build >&2
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
root="$stage/$name"
mkdir -p "$root"

# tracked and untracked-but-not-ignored files only: node_modules, data and local secrets never ship
git ls-files --cached --others --exclude-standard -- \
  package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json \
  'packages/*/package.json' 'packages/*/src/*' \
  apps/admin/package.json apps/admin/tsconfig.json apps/admin/vite.config.ts apps/admin/index.html apps/admin/src \
  examples/toy-domain Dockerfile .dockerignore docker-compose.yml scripts/ops \
  deploy scripts/managed \
  LICENSE THIRD-PARTY-NOTICES.md README.md CHANGELOG.md SECURITY.md \
  docs/DEPLOY.md docs/CONFIGURATION.md docs/API.md docs/RELEASE.md docs/SUPPORT.md docs/MANAGED-OFFER.md \
  | sort -u > "$stage/files"
while IFS= read -r f; do [ -e "$f" ] || { echo "Listed but missing: $f" >&2; exit 1; }; done < "$stage/files"
tar -cf - -T "$stage/files" | tar -xf - -C "$root"
tar -cf - apps/admin/dist | tar -xf - -C "$root"
node scripts/release/sbom.ts --version "$version" --out "$root/sbom.cdx.json"
printf 'name=%s\nversion=%s\ncommit=%s\ndirty=%s\nsource_date_epoch=%s\nnode=%s\npnpm=%s\n' \
  "$name" "$version" "$commit" "$dirty" "$epoch" "$(node --version)" "$(pnpm --version)" > "$root/BUILD-INFO"

# same bytes for the same inputs and tar implementation: fixed order, times, owners and modes, no gzip timestamp
stamp=$(node -e 'const d=new Date(Number(process.argv[1])*1000).toISOString();console.log(d.slice(0,4)+d.slice(5,7)+d.slice(8,10)+d.slice(11,13)+d.slice(14,16)+"."+d.slice(17,19))' "$epoch")
chmod -R u+rwX,go+rX,go-w "$root"
find "$root" -exec touch -h -t "$stamp" {} +
(cd "$stage" && find "$name" | sort > list)
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  (cd "$stage" && tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner -cf - -T list) | gzip -n -9 > "$out/$name.tar.gz"
else
  (cd "$stage" && tar --format ustar --no-recursion --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-mac-metadata -cf - -T list) | gzip -n -9 > "$out/$name.tar.gz"
fi
cp "$root/sbom.cdx.json" "$out/$name.cdx.json"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$out" && sha "$name.tar.gz" "$name.cdx.json" > SHA256SUMS && sha -c SHA256SUMS >&2)

# the tarball must hold what a deployment needs, and its sources must load (dependencies from this checkout)
check=$(mktemp -d "$stage/check.XXXX")
tar -xzf "$out/$name.tar.gz" -C "$check"
for f in Dockerfile docker-compose.yml LICENSE THIRD-PARTY-NOTICES.md sbom.cdx.json BUILD-INFO scripts/ops/backup.sh \
  scripts/ops/archive-crypt.ts deploy/k8s/base/kustomization.yaml deploy/k8s/base/jobs.yaml scripts/managed/new-tenant.sh \
  packages/pdp-http/src/main.ts packages/sql/src/index.ts examples/toy-domain/world.json apps/admin/dist/index.html; do
  [ -e "$check/$name/$f" ] || { echo "Missing from the tarball: $f" >&2; exit 1; }
done
ln -s "$PWD/node_modules" "$check/$name/node_modules"
ln -s "$PWD/packages/pdp-http/node_modules" "$check/$name/packages/pdp-http/node_modules"
(cd "$check/$name" && node -e "import('./packages/pdp-http/src/server.ts').catch((e) => { console.error(e.message); process.exit(1); })")

if [ -n "${RELEASE_SIGNING_HOOK:-}" ]; then
  "$RELEASE_SIGNING_HOOK" "$out/SHA256SUMS"
else
  echo 'UNSIGNED: RELEASE_SIGNING_HOOK is not set (signing key and tool are an owner decision, docs/RELEASE.md)' >&2
fi
ls -l "$out" >&2
