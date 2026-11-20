// Policy version id: canonical JSON (sorted keys) hashed with SHA-256, "pv." + 64 hex. Ids written before SHA-256
// ("pv." + 16 hex, FNV-1a 64) stay readable in audit rows and history; legacyPolicyVersion recomputes them.
// Authenticity of a published bundle is the PDP's Ed25519 signature (docs/API.md, policy signature).
import { createHash } from 'node:crypto';
import type { PolicyBundle } from './types.ts';

export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const entries = Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`);
  return `{${entries.join(',')}}`;
}

export function fnv1a64(text: string): string {
  let h = 0xcbf29ce484222325n;
  const bytes = new TextEncoder().encode(text);
  for (const b of bytes) {
    h ^= BigInt(b);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

const cache = new WeakMap<PolicyBundle, string>();

export function policyVersion(bundle: PolicyBundle): string {
  const hit = cache.get(bundle);
  if (hit) return hit;
  const v = `pv.${createHash('sha256').update(canonical(bundle)).digest('hex')}`;
  cache.set(bundle, v);
  return v;
}

/** The id the bundle had before SHA-256 versions, to match old history entries and audit rows. */
export function legacyPolicyVersion(bundle: PolicyBundle): string {
  return `pv.${fnv1a64(canonical(bundle))}`;
}
