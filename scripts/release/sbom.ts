// CycloneDX 1.5 JSON SBOM of Qadamar from pnpm-lock.yaml (v9) and the installed manifests, no dependency.
//   node scripts/release/sbom.ts --version 0.3.0 [--out file]     (SOURCE_DATE_EPOCH fixes the timestamp)
// Every lockfile package is a component: name, version, purl, SHA-512 hash from the lockfile integrity, licence from the
// installed package.json (absent when the package is not installed on this machine, e.g. another platform's binary).
// Scope "required": shipped, i.e. reachable from the runtime dependencies of packages/pdp-http (server) and apps/admin
// (bundled into the console); "excluded": build, test and type-only tooling.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const SHIPPED_IMPORTERS = ['packages/pdp-http', 'apps/admin'];

export interface Lock {
  importers: Map<string, Map<string, { kind: string; version: string }>>;
  packages: Map<string, { integrity?: string }>;
  snapshots: Map<string, string[]>;
}
const unquote = (s: string): string => s.trim().replace(/^'(.*)'$/, '$1').replace(/^"(.*)"$/, '$1');
/** name@version from a snapshot key or a dependency (name, version with peer suffix). */
export const packageKey = (name: string, version: string): string => `${name}@${version.split('(')[0]}`;
const splitKey = (key: string): { name: string; version: string } => {
  const base = key.split('(')[0]!; const at = base.lastIndexOf('@');
  assert.ok(at > 0, `Unexpected lockfile key: ${key}`);
  return { name: base.slice(0, at), version: base.slice(at + 1) };
};

/** Line parser for the subset of YAML pnpm writes in lockfile v9 (fixed two-space indentation). */
export function parseLock(text: string): Lock {
  const lock: Lock = { importers: new Map(), packages: new Map(), snapshots: new Map() };
  let section = ''; let key = ''; let kind = ''; let dep = '';
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const body = line.trim();
    if (indent === 0) { section = body.replace(/:.*$/, ''); continue; }
    if (indent === 2) {
      key = unquote(body.replace(/:( \{\})?$/, ''));
      if (section === 'importers') lock.importers.set(key, new Map());
      if (section === 'packages') lock.packages.set(key, {});
      if (section === 'snapshots') lock.snapshots.set(key, []);
      continue;
    }
    if (section === 'packages' && indent === 4) {
      const m = body.match(/^resolution: \{.*integrity: ([^,}\s]+)/);
      if (m) lock.packages.get(key)!.integrity = m[1]!;
    } else if (section === 'importers') {
      if (indent === 4) kind = body.replace(/:$/, '');
      else if (indent === 6) dep = unquote(body.replace(/:$/, ''));
      else if (indent === 8 && body.startsWith('version:')) lock.importers.get(key)!.set(dep, { kind, version: unquote(body.slice(8)) });
    } else if (section === 'snapshots') {
      if (indent === 4) kind = body.replace(/:.*$/, '');
      else if (indent === 6 && (kind === 'dependencies' || kind === 'optionalDependencies')) {
        const colon = body.startsWith("'") ? body.indexOf("':") + 1 : body.indexOf(':');
        lock.snapshots.get(key)!.push(packageKey(unquote(body.slice(0, colon)), unquote(body.slice(colon + 1))));
      }
    }
  }
  return lock;
}

/** Package keys reachable from the given importers' runtime dependencies. */
export function shipped(lock: Lock, importers: readonly string[]): Set<string> {
  const seen = new Set<string>(); const todo: string[] = [];
  for (const id of importers) {
    for (const [name, d] of lock.importers.get(id) ?? []) if (d.kind === 'dependencies' && !d.version.startsWith('link:')) todo.push(packageKey(name, d.version));
  }
  const byBase = new Map<string, string[]>();
  for (const [snap, deps] of lock.snapshots) { const k = packageKey(splitKey(snap).name, splitKey(snap).version); byBase.set(k, [...(byBase.get(k) ?? []), ...deps]); }
  while (todo.length) { const k = todo.pop()!; if (seen.has(k)) continue; seen.add(k); todo.push(...(byBase.get(k) ?? [])); }
  return seen;
}

export const purl = (name: string, version: string): string => `pkg:npm/${name.replace(/^@/, '%40')}@${encodeURIComponent(version)}`;
const ALGORITHMS: Record<string, string> = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
export function hashOf(integrity: string | undefined): Array<{ alg: string; content: string }> {
  const m = integrity?.match(/^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/);
  return m ? [{ alg: ALGORITHMS[m[1]!]!, content: Buffer.from(m[2]!, 'base64').toString('hex') }] : [];
}

/** The licence field of the installed manifest, from pnpm's virtual store (node_modules/.pnpm/<name+>@<version>[_peers]). */
function licenceOf(name: string, version: string): string | undefined {
  const store = join(ROOT, 'node_modules/.pnpm');
  const prefix = `${name.replace('/', '+')}@${version}`;
  const dir = existsSync(store) ? readdirSync(store).find((d) => d === prefix || d.startsWith(`${prefix}_`) || d.startsWith(`${prefix}(`)) : undefined;
  if (!dir) return undefined;
  const manifest = join(store, dir, 'node_modules', name, 'package.json');
  if (!existsSync(manifest)) return undefined;
  const license: unknown = (JSON.parse(readFileSync(manifest, 'utf8')) as { license?: unknown }).license;
  return typeof license === 'string' && license.trim() ? license.trim() : undefined;
}

export function sbom(lockText: string, version: string, timestamp: string, licence = licenceOf): Record<string, unknown> {
  const lock = parseLock(lockText);
  const required = shipped(lock, SHIPPED_IMPORTERS);
  const sortKey = (key: string): string => `${splitKey(key).name}\u0000${splitKey(key).version}`;
  const components = [...lock.packages.keys()].sort((a, b) => (sortKey(a) < sortKey(b) ? -1 : 1)).map((key) => {
    const { name, version: v } = splitKey(key);
    const ref = purl(name, v); const spdx = licence(name, v);
    return { type: 'library', 'bom-ref': ref, name, version: v, scope: required.has(key) ? 'required' : 'excluded', purl: ref,
      hashes: hashOf(lock.packages.get(key)!.integrity), ...(spdx ? { licenses: [{ expression: spdx }] } : {}) };
  });
  const refOf = new Map([...lock.packages.keys()].map((key) => [key, purl(splitKey(key).name, splitKey(key).version)]));
  const depends = new Map<string, Set<string>>();
  for (const [snap, deps] of lock.snapshots) {
    const ref = refOf.get(packageKey(splitKey(snap).name, splitKey(snap).version));
    if (!ref) continue;
    const set = depends.get(ref) ?? new Set<string>();
    for (const d of deps) { const r = refOf.get(d); if (r) set.add(r); }
    depends.set(ref, set);
  }
  const rootRef = `pkg:generic/qadamar/qadamar@${encodeURIComponent(version)}`;
  const direct = [...required].filter((k) => SHIPPED_IMPORTERS.some((i) => [...(lock.importers.get(i) ?? [])].some(([n, d]) => d.kind === 'dependencies' && packageKey(n, d.version) === k)));
  const serial = createHash('sha256').update(`${lockText}\0${version}\0${timestamp}`).digest('hex');
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    serialNumber: `urn:uuid:${serial.slice(0, 8)}-${serial.slice(8, 12)}-5${serial.slice(13, 16)}-8${serial.slice(17, 20)}-${serial.slice(20, 32)}`,
    metadata: {
      timestamp,
      tools: { components: [{ type: 'application', name: 'scripts/release/sbom.ts', description: 'Qadamar SBOM generator (pnpm-lock.yaml v9)' }] },
      component: { type: 'application', 'bom-ref': rootRef, name: 'qadamar', version, purl: rootRef,
        licenses: [{ license: { id: 'Apache-2.0' } }] },
    },
    components,
    dependencies: [{ ref: rootRef, dependsOn: direct.map((k) => refOf.get(k)!).filter(Boolean).sort() },
      ...[...depends].sort(([a], [b]) => a.localeCompare(b)).map(([ref, set]) => ({ ref, dependsOn: [...set].sort() }))],
  };
}

// self-check of the parser on a lockfile fragment
{
  const sample = ["lockfileVersion: '9.0'", 'importers:', '  packages/pdp-http:', '    dependencies:', '      pg:', '        specifier: 1.0.0', '        version: 1.0.0',
    '    devDependencies:', "      '@types/pg':", '        specifier: 1.0.0', '        version: 1.0.0', 'packages:',
    '  pg@1.0.0:', '    resolution: {integrity: sha512-' + Buffer.alloc(64, 1).toString('base64') + '}', "  '@types/pg@1.0.0':", '    resolution: {integrity: sha1-AAAA}', '  pg-int8@1.0.1:',
    '    resolution: {integrity: sha512-' + Buffer.alloc(64, 2).toString('base64') + '}', 'snapshots:', '  pg@1.0.0:', '    dependencies:', '      pg-int8: 1.0.1', "  '@types/pg@1.0.0': {}", '  pg-int8@1.0.1: {}', ''].join('\n');
  const doc = sbom(sample, '9.9.9', '2026-01-01T00:00:00Z', () => 'MIT') as { components: Array<{ name: string; scope: string; purl: string; hashes: Array<{ content: string }> }> };
  assert.deepEqual(doc.components.map((c) => [c.name, c.scope]), [['@types/pg', 'excluded'], ['pg', 'required'], ['pg-int8', 'required']]);
  assert.equal(doc.components[0]!.purl, 'pkg:npm/%40types/pg@1.0.0');
  assert.equal(doc.components[1]!.hashes[0]!.content, '01'.repeat(64));
}

function main(): void {
  const args = process.argv.slice(2);
  const arg = (flag: string): string | undefined => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
  const version = arg('--version') ?? (JSON.parse(readFileSync(join(ROOT, 'packages/pdp-http/package.json'), 'utf8')) as { version: string }).version;
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) throw new Error(`Invalid version: ${version}`);
  const epoch = process.env.SOURCE_DATE_EPOCH;
  if (epoch !== undefined && !/^\d+$/.test(epoch)) throw new Error('SOURCE_DATE_EPOCH must be a Unix time in seconds');
  const timestamp = new Date(epoch === undefined ? Date.now() : Number(epoch) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const doc = sbom(readFileSync(join(ROOT, 'pnpm-lock.yaml'), 'utf8'), version, timestamp);
  const components = doc.components as Array<{ 'bom-ref': string; hashes: unknown[]; licenses?: unknown; scope: string }>;
  assert.ok(components.length > 0, 'No component found in pnpm-lock.yaml');
  assert.equal(new Set(components.map((c) => c['bom-ref'])).size, components.length, 'Duplicate bom-ref');
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  const out = arg('--out');
  if (out) writeFileSync(out, text); else process.stdout.write(text);
  const count = (f: (c: (typeof components)[number]) => boolean): number => components.filter(f).length;
  console.error(`sbom: ${components.length} components (${count((c) => c.scope === 'required')} required), ${count((c) => c.hashes.length > 0)} with a hash, ${count((c) => c.licenses !== undefined)} with a licence`);
}
main();
