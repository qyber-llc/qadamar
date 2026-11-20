import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, appendFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const lock = JSON.parse(readFileSync(new URL('./playwright-lock.json', import.meta.url), 'utf8'));
/** Verify every archive before extraction; the browser installer must never make an unpinned download. */
function download(url: string, path: string, algorithm: string, expected: string, encoding: 'hex' | 'base64'): void {
  execFileSync('curl', ['--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '120', '--proto', '=https', '--proto-redir', '=https', '--output', path, url]);
  verifyArchive(readFileSync(path), algorithm, expected, encoding);
}

export function verifyArchive(bytes: Uint8Array, algorithm: string, expected: string, encoding: 'hex' | 'base64'): void {
  const actual = createHash(algorithm).update(bytes).digest(encoding);
  if (actual !== expected) throw new Error(`CI ${algorithm} archive checksum mismatch`);
}

export function browserArchive(platform: string, checksum: string | undefined): { url: string; checksum: string } {
  if (!['mac-arm64', 'linux64'].includes(platform)) throw new Error('Unsupported CI Chromium platform');
  if (!/^[a-f0-9]{64}$/.test(checksum ?? '')) throw new Error('Provision CI_CHROMIUM_SHA256 for this runner before enabling CI: see docs/CI.md. Browser downloads without an archive pin are refused.');
  return { url: `https://storage.googleapis.com/chrome-for-testing-public/${lock.chromiumVersion}/${platform}/chrome-headless-shell-${platform}.zip`, checksum: checksum! };
}

function install(): void {
  if (!process.env.GITHUB_ENV) throw new Error('This installer is for GitHub CI only');
  const platform = process.platform === 'darwin' && process.arch === 'arm64' ? 'mac-arm64'
    : process.platform === 'linux' && process.arch === 'x64' ? 'linux64' : '';
  if (!platform) throw new Error('Unsupported CI Chromium platform');
  const bin = resolve('.ci-bin');
  const core = join(bin, 'playwright-core');
  const taskTmp = mkdtempSync(join(tmpdir(), 'gate-playwright-'));
  mkdirSync(core, { recursive: true });
  try {
    const archive = join(taskTmp, 'playwright.tgz');
    download(`https://registry.npmjs.org/playwright-core/-/playwright-core-${lock.version}.tgz`, archive, 'sha512', lock.integrity.slice('sha512-'.length), 'base64');
    execFileSync('tar', ['-xzf', archive, '--strip-components=1', '-C', core]);
    const require = createRequire(import.meta.url);
    require(core);
    const cached = process.platform === 'darwin'
      ? join(homedir(), 'Library/Caches/ms-playwright', `chromium_headless_shell-${lock.chromiumRevision}`, 'chrome-headless-shell-mac-arm64/chrome-headless-shell') : '';
    const cachedVerified = cached && existsSync(cached)
      && createHash('sha256').update(readFileSync(cached)).digest('hex') === lock.darwinArm64ExecutableSha256;
    let browsersPath: string | undefined;
    if (!cachedVerified) {
      // both archive digests are pinned in the lock file (recorded 2026-11-11); a runner variable may override them
      const pinned = browserArchive(platform, process.env.CI_CHROMIUM_SHA256 || (platform === 'linux64' ? lock.linux64ArchiveSha256 : lock.macArm64ArchiveSha256));
      const browserZip = join(taskTmp, 'chromium.zip');
      download(pinned.url, browserZip, 'sha256', pinned.checksum, 'hex');
      browsersPath = join(bin, 'browsers');
      const destination = join(browsersPath, `chromium_headless_shell-${lock.chromiumRevision}`);
      mkdirSync(destination, { recursive: true });
      execFileSync('unzip', ['-q', '-o', browserZip, '-d', destination]);
    }
    if (JSON.parse(readFileSync(join(core, 'package.json'), 'utf8')).version !== lock.version) throw new Error('Playwright version mismatch');
    const browsers = JSON.parse(readFileSync(join(core, 'browsers.json'), 'utf8')).browsers;
    if (!browsers.some((b: { name: string; revision: string; browserVersion: string }) => b.name === 'chromium-headless-shell' && b.revision === lock.chromiumRevision && b.browserVersion === lock.chromiumVersion)) throw new Error('Chromium revision mismatch');
    appendFileSync(process.env.GITHUB_ENV, `PLAYWRIGHT_CORE_PATH=${core}\nE2E_REQUIRED=1\n${browsersPath ? `PLAYWRIGHT_BROWSERS_PATH=${browsersPath}\n` : ''}`);
    console.log(`Provided Playwright ${lock.version}, Chromium ${lock.chromiumVersion} (${cachedVerified ? 'verified runner cache' : 'verified archive'}); browser checks are required.`);
  } finally {
    rmSync(taskTmp, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) install();
