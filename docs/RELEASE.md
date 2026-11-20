# Releases

A release is three files attached to a GitHub release, built by `scripts/release/pack.sh` from a tagged commit:

| File | What |
|---|---|
| `qadamar-X.Y.Z.tar.gz` | The deployable server: sources (`packages/*`, the console sources), the **built console** (`apps/admin/dist`), `examples/toy-domain` (the seed `WORLD_DIR`), `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `scripts/ops`, the managed-offer manifests and scripts (`deploy/`, `scripts/managed`), `LICENSE`, `THIRD-PARTY-NOTICES.md`, the SBOM (`sbom.cdx.json`), `BUILD-INFO` (version, commit, dirty flag, `SOURCE_DATE_EPOCH`, Node and pnpm versions) and the operator docs (README, CHANGELOG, SECURITY, DEPLOY, CONFIGURATION, API, RELEASE, SUPPORT, MANAGED-OFFER). |
| `qadamar-X.Y.Z.cdx.json` | The same SBOM, CycloneDX 1.5 JSON, from `scripts/release/sbom.ts`. |
| `SHA256SUMS` | SHA-256 of the two files above. |

Not in the tarball: `node_modules` (install with `pnpm install --frozen-lockfile --prod --filter @product/pdp-http...`, or
`docker build` the unpacked directory), a container image (none is built or pushed), tests and design documents. The
deployment files are `Dockerfile` and `docker-compose.yml` at the root (DEPLOY.md) and the Kubernetes manifests of the
managed offer in `deploy/k8s` (MANAGED-OFFER.md).

## SBOM

`node scripts/release/sbom.ts --version X.Y.Z [--out file]` reads `pnpm-lock.yaml` (lockfile v9) and the installed
manifests; no dependency. Every lockfile package is a component with name, version, `purl` (`pkg:npm/...`) and a
SHA-512 hash taken from the lockfile `integrity`. The licence is the installed `package.json` `license` field, written
as an SPDX expression; packages not installed on the build machine (other platforms' native binaries of the build
tools) have no licence entry. `scope` is `required` for what ships (reachable from the runtime dependencies of
`packages/pdp-http` and of `apps/admin`, whose React is bundled into the console) and `excluded` for build, test and
type-only tooling. The application itself is the `metadata.component`, under the proprietary `LICENSE`. The output
was not validated against the CycloneDX JSON schema (no network when written); the script checks its own structure
(unique `bom-ref`, hashes, parser self-test).

## Cutting a release (owner)

1. Set the same version in `packages/pdp-http/package.json` (the server version the tag must match) and, by
   convention, every other workspace manifest; add the CHANGELOG entry; merge to `main` through CI.
2. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`. Tag a commit already on `main`: the release job refuses any other.
3. `.github/workflows/release.yml` runs on the same runner as CI (`runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}`):
   the secret scan, `pnpm install --frozen-lockfile`, a throwaway PostgreSQL and `tools/ci/checks.sh` (the whole CI
   gate), then a separate read-only job builds the default Dockerfile image, exports it with `docker save` and scans the
   tar with tag-and-digest-pinned Trivy (fixable HIGH/CRITICAL block; [CI.md](CI.md)). No Docker socket is mounted into
   the scanner. Only after that scan and the `formal` job (Lean proofs and the differential test, [CI.md](CI.md), which
   downloads and runs the Lean toolchain with `contents: read` only) pass do `pack.sh vX.Y.Z` and `gh release create`
   attach the three files (and the signature files when signing is configured). It needs the **`gh` CLI on the
   runner**: GitHub-hosted Ubuntu has it; the self-hosted Mac needs `brew install gh`. Only the publish job has
   `contents: write`; it downloads no toolchain and mounts no Docker socket; the formal, test and scan jobs have
   `contents: read`.

Locally, without GitHub: `bash scripts/release/pack.sh` after `pnpm install` (a dirty tree is refused; `ALLOW_DIRTY=1`
for a trial, recorded in `BUILD-INFO`). Outputs go to `dist/release/X.Y.Z/` (`OUT_DIR` overrides); existing files
are never overwritten.

## Verifying a release (buyer)

```sh
shasum -a 256 -c SHA256SUMS            # or sha256sum -c SHA256SUMS
tar -xzf qadamar-X.Y.Z.tar.gz && cat qadamar-X.Y.Z/BUILD-INFO
```

- `BUILD-INFO` names the commit; `dirty=false` for anything built by the workflow.
- **Reproducible with the same tar implementation:** files are sorted, owners are 0, modes normalised, every time is
  `SOURCE_DATE_EPOCH` (the commit time unless set) and gzip carries no timestamp. Checking out the commit, running
  `pnpm install --frozen-lockfile` and `SOURCE_DATE_EPOCH=<from BUILD-INFO> bash scripts/release/pack.sh vX.Y.Z`
  should give the same SHA-256. Verified so far: two runs on one macOS machine (bsdtar) gave identical bytes. GNU tar
  (Linux runner) takes its own branch and produces different bytes from bsdtar; it was not run here. The built
  console is part of the bytes, so the same Node, pnpm and lockfile are needed.
- Checksums alone prove the files match the release page, not who published it. That needs the signature below.

## Signing (owner decision)

Releases from 0.12.1 are **signed** (owner decision, 2026-11-17): `SHA256SUMS.sig` is an SSH signature
(`ssh-keygen -Y sign`, namespace `file`) made with an ed25519 key that stays on the release runner. The earlier
published releases (0.8.3, 0.9.2, 0.10.1, 0.11.0) were signed **after the fact** on 2026-11-17 (owner decision) by a
one-off job on the same runner: it downloaded each release, checked every file against that release's own `SHA256SUMS`
and that the file lists match, then attached `SHA256SUMS.sig`. That signature attests the files exactly as they were
published; it was made later than the release and does not prove who built them at the time. The `v0.12.0` tag has no
release (its signing step failed). Verify a download with OpenSSH 8.1 or later, then the checksums:

```
ssh-keygen -Y verify -f allowed_signers -I release@qadamar -n file -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
```

`allowed_signers` is a file holding this one line (also `scripts/release/allowed_signers` in the repository; this
page ships in the release tarball):

```
release@qadamar namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJnbPXWjIWv6WwK8JcfqTbkX2/t9sXR7tNMUGHBj1iFL
```

(key fingerprint `SHA256:U/RyBx903hqHtefYsdz4E8w1miTh+im23nQHSU6S3ew`). The private key is encrypted at
`~/.config/qadamar/release-signing/release_ed25519` on the release runner (runner user), and it
is not in the repository or in GitHub. Its passphrase is the repository secret `RELEASE_SSH_KEY_PASSPHRASE`, passed
only to the packaging step of the release job (the headless runner has no usable Keychain); the hook falls back to the
login Keychain item `qadamar-release-signing` when the variable is unset. Neither the file nor the secret alone
can sign.
The hook is `scripts/release/sign-ssh.sh`, set as the repository variable `RELEASE_SIGNING_HOOK`; it checks the
signature against the committed `allowed_signers` before the release is published. Rotation: create a new key, replace
the line in `allowed_signers`, and say in the CHANGELOG from which version the new key signs; a revoked key is removed
from that file (older releases then verify only with the old line, kept in git history). The hook mechanism:

- `RELEASE_SIGNING_HOOK`: path to an executable on the runner. `pack.sh` runs it as
  `"$RELEASE_SIGNING_HOOK" <out>/SHA256SUMS` after the checksums are written; it must write its signature file(s) next
  to `SHA256SUMS` (for example `SHA256SUMS.sig`), and a non-zero exit fails the release. The workflow passes the
  repository variable `vars.RELEASE_SIGNING_HOOK` and attaches every `SHA256SUMS.*` file. Unset, `pack.sh` prints
  `UNSIGNED` and the release carries no signature.
- Residual risk (stated, not solved): every CI job on that Mac, pull requests included, runs as the same user as the
  release job, so code run by a job (a changed script, or a dependency's install script) can read the encrypted key
  and, in a workflow given the secret, its passphrase, and sign anything until the key is rotated. Today only the owner has write access and fork
  pull requests run no workflow, which limits who can start such code. Not done (owner decisions, hosting): a separate
  runner user or machine for releases, a hardware-held key (HSM or token), protected `v*` tags and a reviewer-gated
  release environment, a second signer.

## Variables

| Variable | Used by | Meaning |
|---|---|---|
| `RELEASE_SIGNING_HOOK` | `pack.sh`, `release.yml` (`vars.`) | Signing command run on `SHA256SUMS`; unset = unsigned. |
| `SOURCE_DATE_EPOCH` | `pack.sh`, `sbom.ts` | Timestamp of every file and of the SBOM; default the commit time (`pack.sh`) or now (`sbom.ts` alone). |
| `ALLOW_DIRTY` | `pack.sh` | `1` packs a work tree with uncommitted changes (trial only; `BUILD-INFO` says `dirty=true`). |
| `OUT_DIR` | `pack.sh` | Output directory, default `dist/release/X.Y.Z` (git-ignored). |
