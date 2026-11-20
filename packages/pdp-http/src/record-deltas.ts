import type { Resource, Subject, Tuple } from '../../core/src/index.ts';

export interface StoredTuple extends Tuple { readonly id: string }
export type RecordKind = 'subject' | 'resource' | 'tuple';
export type RecordValue = Subject | Resource | StoredTuple;
export interface RecordDelta {
  readonly kind: RecordKind;
  readonly op: 'put' | 'delete';
  readonly type: string;
  readonly id: string;
  readonly value?: RecordValue;
  /** Storage order, assigned at commit; `move` is the conservative fallback for an unannotated reorder. */
  readonly position?: number;
  readonly move?: boolean;
}
export interface RecordState {
  readonly subjects: readonly Subject[];
  readonly resources: readonly Resource[];
  readonly tuples: readonly StoredTuple[];
}

const DELTAS = Symbol('gate.recordDeltas');
const APPLIED = Symbol('gate.recordDeltasApplied');
export function withRecordDeltas<T extends RecordState>(state: T, deltas: readonly RecordDelta[], applied = false): T {
  Object.defineProperty(state, DELTAS, { value: deltas, configurable: true });
  Object.defineProperty(state, APPLIED, { value: applied, configurable: true });
  return state;
}
export const recordDeltasOf = (state: RecordState): readonly RecordDelta[] | undefined =>
  (state as RecordState & { [DELTAS]?: readonly RecordDelta[] })[DELTAS];
export const recordDeltasApplied = (state: RecordState): boolean =>
  (state as RecordState & { [APPLIED]?: boolean })[APPLIED] === true;

export const recordKey = (kind: RecordKind, type: string, id: string): string => JSON.stringify([kind, type, id]);
const keyOf = (kind: RecordKind, value: RecordValue): string =>
  recordKey(kind, kind === 'tuple' ? '' : (value as Subject | Resource).type, value.id);

/** Unknown transitions keep their old, correct whole-record behaviour; annotated writes never pay this diff. */
export function diffRecordDeltas(before: RecordState, after: RecordState): RecordDelta[] {
  const out: RecordDelta[] = [];
  for (const [kind, previous, next] of [
    ['subject', before.subjects, after.subjects],
    ['resource', before.resources, after.resources],
    ['tuple', before.tuples, after.tuples],
  ] as const) {
    const old = new Map(previous.map((value) => [keyOf(kind, value), value]));
    const live = new Set(next.map((value) => keyOf(kind, value)));
    for (const [key, value] of old) if (!live.has(key)) {
      const [, type, id] = JSON.parse(key) as [RecordKind, string, string];
      out.push({ kind, op: 'delete', type, id, value });
    }
    for (const [at, value] of next.entries()) {
      const key = keyOf(kind, value);
      const [, type, id] = JSON.parse(key) as [RecordKind, string, string];
      if (old.get(key) !== value || previous[at] !== value) out.push({ kind, op: 'put', type, id, value, move: true });
    }
  }
  return out;
}
