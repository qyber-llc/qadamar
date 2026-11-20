// The audit API's type filter accepts every row type the server writes. The test walks the server source for the type
// of every audit append (literals and the branches of a computed type), then queries the filter with each one.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { audit } from '../src/admin/audit.ts';
import { AUDIT_TYPES, type AuditType } from '../src/audit.ts';
import { HttpError } from '../src/http.ts';
import { fixture, users } from './helpers.ts';

function writtenTypes(): Set<string> {
  const src = resolve(import.meta.dirname, '../src');
  const files = readdirSync(src, { recursive: true, encoding: 'utf8' }).filter((f) => f.endsWith('.ts'));
  const out = new Set<string>();
  for (const file of files) {
    const text = readFileSync(resolve(src, file), 'utf8');
    // an audit event is an object literal opening with type then actor (append calls and rows a store writes itself);
    // its values are the literals that start the type expression or follow `?` or `:`
    for (const m of text.matchAll(/\{\s*type:([^{}]{1,600}?),\s*actor\b/g)) {
      for (const lit of (':' + (m[1] ?? '')).matchAll(/[?:]\s*'([a-z_]+)'/g)) out.add(lit[1]!);
    }
  }
  return out;
}

test('every audit row type the server writes is accepted by the audit API type filter, and nothing else', async (t) => {
  const written = writtenTypes();
  assert.ok(written.size >= 6, `found ${[...written].join(', ')}`);
  assert.deepEqual([...written].sort(), [...AUDIT_TYPES].sort(), 'AUDIT_TYPES lists exactly the written types');
  const { rt } = fixture(t);
  for (const type of AUDIT_TYPES) rt.audit.append({ type, actor: 'test', action: 'walk' });
  for (const type of written) {
    const page = await audit(rt, users.sam, new URL(`http://x/admin/v1/audit?type=${type}&limit=1000`)) as { items: Array<{ type: string }> };
    assert.ok(page.items.length > 0 && page.items.every((r) => r.type === type), type);
  }
  assert.throws(() => audit(rt, users.sam, new URL('http://x/admin/v1/audit?type=unknown')), (e: unknown) => e instanceof HttpError && e.status === 400);
  const typed: AuditType = 'simulation'; void typed;
});
