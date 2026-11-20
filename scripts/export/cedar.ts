// Cedar export of a policy bundle (docs/spec/POLICY-LANGUAGE.md, appendix A).
//   node scripts/export/cedar.ts <bundle.json>              prints { schema, policies, unsupported } as JSON
//   node scripts/export/cedar.ts <bundle.json> --out <dir>  writes policies.cedar, schema.cedarschema.json, unsupported.json
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { toCedar, validateBundle } from '../../packages/core/src/index.ts';

const [file, flag, dir] = process.argv.slice(2);
if (!file || (flag !== undefined && (flag !== '--out' || !dir))) {
  console.error('usage: node scripts/export/cedar.ts <bundle.json> [--out <dir>]');
  process.exit(2);
}
const input: unknown = JSON.parse(readFileSync(file, 'utf8'));
const valid = validateBundle(input);
if (!valid.ok) { console.error(valid.errors.join('\n')); process.exit(1); }
// validateBundle 1.0 tolerates these absent (the engine then denies everything); the export would not match that.
// Content-attribute rules (abacContent, legacy cbac) may be absent: none then apply, in the engine and in the export.
const missing = (['abac', 'sod'] as const).filter((k) => !Array.isArray(valid.bundle[k]));
if (missing.length > 0) { console.error(`not a conforming bundle, missing ${missing.join(', ')} (POLICY-LANGUAGE.md §9.3)`); process.exit(1); }
const out = toCedar(valid.bundle);
if (dir) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'policies.cedar'), out.policies);
  writeFileSync(join(dir, 'schema.cedarschema.json'), `${JSON.stringify(out.schema, null, 2)}\n`);
  writeFileSync(join(dir, 'unsupported.json'), `${JSON.stringify(out.unsupported, null, 2)}\n`);
  console.error(`wrote ${dir}: ${out.unsupported.length} unsupported item(s), see unsupported.json`);
} else {
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}
