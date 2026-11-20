import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AccessDeniedError, MASKED_TEXT, ObligationError, PdpResponseError, PepError, enforce,
} from '../src/index.ts';
import type { Evaluation, JsonObject, Obligations } from '../src/index.ts';

function allowed(obligations: Partial<Obligations> = {}): Evaluation {
  return {
    decision: true,
    context: {
      rules: ['viewer'], reasons: ['fixture'], obligations: {
        redact: [], maskClasses: [], notify: [], ...obligations,
      }, policy_version: 'pv.test', would_deny: [],
    },
  };
}

test('allow deep-clones the JSON record and redacts top-level and dotted fields as null', () => {
  const original = {
    title: 'Case', informant_name: 'Sensitive Name', nested: { secret: 'hidden', visible: 42 },
    content: [{ class: 'public.summary', text: 'summary' }],
  };
  const result = enforce(allowed({ redact: ['informant_name', 'nested.secret'] }), original);
  assert.notEqual(result, original);
  assert.notEqual(result.nested, original.nested);
  assert.notEqual(result.content, original.content);
  assert.equal(result.informant_name, null);
  assert.deepEqual(result.nested, { secret: null, visible: 42 });
  assert.equal(original.informant_name, 'Sensitive Name');
  assert.equal(original.nested.secret, 'hidden');
});

test('fieldAllowlist retains only selected dotted fields and composes with redaction', () => {
  const record = { title: 'Case', private: 'no', nested: { visible: 'yes', secret: 'no', amount: 20 } };
  const selected = enforce(allowed({ fieldAllowlist: ['title', 'nested.visible'] }), record);
  assert.deepEqual(selected, { title: 'Case', nested: { visible: 'yes' } });
  const redacted = enforce(allowed({ fieldAllowlist: ['nested'], redact: ['nested.secret'] }), record);
  assert.deepEqual(redacted, { nested: { visible: 'yes', secret: null, amount: 20 } });
  assert.deepEqual(enforce(allowed({ fieldAllowlist: [] }), record), {});
  assert.deepEqual(record.nested, { visible: 'yes', secret: 'no', amount: 20 });
});

test('maskClasses masks every matching explicit content fragment and preserves other text', () => {
  const original = {
    content: [
      { class: 'finance.amount', text: 'AED 900,000' },
      { class: 'public.summary', text: 'Procurement summary' },
      { class: 'finance.amount', text: 'AED 12' },
    ],
  };
  const result = enforce(allowed({ maskClasses: ['finance.amount'] }), original);
  assert.deepEqual(result.content, [
    { class: 'finance.amount', text: MASKED_TEXT },
    { class: 'public.summary', text: 'Procurement summary' },
    { class: 'finance.amount', text: MASKED_TEXT },
  ]);
  assert.equal(original.content[0]?.text, 'AED 900,000');
});

test('masking refuses absent, unlocated, or malformed content instead of pretending success', () => {
  const records: JsonObject[] = [
    {}, { content: [] }, { content: [{ class: 'public.summary', text: 'safe' }] },
    { content: 'AED 900,000' }, { content: [{ class: 'finance.amount' }] },
    { content: [{ text: 'AED 900,000' }] }, { content: [{ class: 'finance.amount', text: null }] },
  ];
  for (const record of records) {
    assert.throws(() => enforce(allowed({ maskClasses: ['finance.amount'] }), record), ObligationError);
  }
  assert.throws(
    () => enforce(allowed({ fieldAllowlist: ['title'], maskClasses: ['finance.amount'] }), { title: 'no content returned' }),
    ObligationError,
  );
});

test('deny always refuses and never returns or mutates the record', () => {
  const denied: Evaluation = { ...allowed(), decision: false };
  const record = { informant_name: 'Sensitive Name' };
  assert.throws(() => enforce(denied, record), (error: unknown) => {
    assert.ok(error instanceof AccessDeniedError);
    assert.equal(error.code, 'access_denied');
    assert.doesNotMatch(error.message, /Sensitive Name/);
    return true;
  });
  assert.deepEqual(record, { informant_name: 'Sensitive Name' });
});

test('malformed decisions and unknown obligation keys fail closed', () => {
  const malformed: unknown[] = [
    null, {}, { decision: 'true' }, { decision: true },
    { ...allowed(), context: undefined },
    { ...allowed(), context: { ...allowed().context, obligations: { redact: 'informant_name', maskClasses: [], notify: [] } } },
    { ...allowed(), context: { ...allowed().context, obligations: { redact: [], maskClasses: [], notify: [], unexpected: [] } } },
    { ...allowed(), context: { ...allowed().context, rules: 'viewer' } },
    { ...allowed(), context: { ...allowed().context, policy_version: 7 } },
  ];
  for (const decision of malformed) {
    assert.throws(() => enforce(decision as Evaluation, { value: 'not released' }), (error: unknown) => {
      assert.ok(error instanceof PepError);
      assert.ok(error instanceof PdpResponseError || error instanceof AccessDeniedError);
      return true;
    });
  }
});

test('unsupported notification obligations refuse, while decision-token metadata does not alter a read record', () => {
  assert.throws(() => enforce(allowed({ notify: ['security-officer'] }), { value: 1 }), ObligationError);
  assert.deepEqual(enforce(allowed({ decisionToken: { ttlSeconds: 15, resourceVersion: 8 } }), { value: 1 }, { decisionTokenConsumed: true }), { value: 1 });
});

test('field paths are own-property-only and reject prototype-related or malformed segments', () => {
  for (const field of ['__proto__.secret', 'constructor.prototype.secret', '.secret', 'secret.', 'a..b']) {
    assert.throws(() => enforce(allowed({ redact: [field] }), { value: 1 }), ObligationError);
  }
  const missing = enforce(allowed({ redact: ['toString', 'nested.missing'] }), { value: 1 });
  assert.deepEqual(missing, { value: 1 });
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});

test('a redaction path that crosses an array refuses instead of releasing the field, and the record must be an object', () => {
  assert.throws(() => enforce(allowed({ redact: ['owner.ssn'] }), { owner: [{ ssn: '123' }] }), ObligationError);
  assert.throws(() => enforce(allowed(), [{ ssn: '123' }] as unknown as JsonObject), ObligationError);
});

test('non-JSON, cyclic, non-finite, sparse, and excessively nested records are refused', () => {
  const cyclic: { self?: unknown } = {}; cyclic.self = cyclic;
  const sparse: unknown[] = []; sparse.length = 1;
  const deep: { next?: unknown } = {}; let cursor = deep;
  for (let index = 0; index < 110; index++) { const next = {}; cursor.next = next; cursor = next; }
  const invalid = [
    { value: undefined }, { value: 1n }, { value: () => true }, { value: Number.NaN },
    { value: Number.POSITIVE_INFINITY }, { value: new Date() }, cyclic, { value: sparse }, deep,
  ];
  for (const record of invalid) assert.throws(() => enforce(allowed(), record as JsonObject), ObligationError);
});

test('a decisionToken obligation is refused unless the caller acknowledges its consumption; notify stays refused', () => {
  const decision = allowed({ decisionToken: { ttlSeconds: 60, resourceVersion: 1 } });
  assert.throws(() => enforce(decision, { a: 1 }), (error) => error instanceof ObligationError && /single-use/.test(error.message));
  assert.deepEqual(enforce(decision, { a: 1 }, { decisionTokenConsumed: true }), { a: 1 });
  assert.throws(() => enforce(allowed({ notify: ['x'] }), { a: 1 }, { decisionTokenConsumed: true }), ObligationError);
});
