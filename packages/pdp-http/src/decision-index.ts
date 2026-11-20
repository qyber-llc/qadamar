import { indexTuples, patchTupleIndex, type Graph, type TupleIndexChange } from '../../core/src/index.ts';
import type { Ref, Resource, Subject } from '../../core/src/index.ts';
import type { RecordDelta, RecordState, StoredTuple } from './record-deltas.ts';

interface Position { at: number; version: number }
interface Lookup {
  byId: Map<string, unknown>;
  byKey: Map<string, unknown>;
  positions: Map<string, Position>;
  children: Map<string, Set<string>>;
  deletions: number[];
}
type Listed = Subject | Resource | StoredTuple;
const lookups = new WeakMap<readonly Listed[], Lookup>();
/** What each in-place patch of a list replaced, newest last, until the store's next commit point: a failed request
 *  restores its saved state by undoing these (the saved state shares the patched arrays, so reassigning it is not enough). */
type Undo = { op: 'pop' } | { op: 'set' | 'insert'; at: number; old: Listed };
const journals = new WeakMap<readonly Listed[], Undo[]>();
const record = (list: readonly Listed[], undo: Undo): void => {
  const journal = journals.get(list);
  if (journal) journal.push(undo); else journals.set(list, [undo]);
};
const typedKey = (value: Listed): string => JSON.stringify('object' in value ? ['tuple', value.id] : [value.type, value.id]);
const refKey = (value: Ref): string => JSON.stringify([value.type, value.id]);

function lookup(list: readonly Listed[]): Lookup {
  let index = lookups.get(list);
  if (!index) {
    index = { byId: new Map(), byKey: new Map(), positions: new Map(), children: new Map(), deletions: [] };
    for (const [at, value] of list.entries()) {
      if (!index.byId.has(value.id)) index.byId.set(value.id, value);
      if (!index.byKey.has(typedKey(value))) index.byKey.set(typedKey(value), value);
      index.positions.set(typedKey(value), { at, version: 0 });
      if ('parent' in value && value.parent) {
        const parent = refKey(value.parent);
        index.children.set(parent, (index.children.get(parent) ?? new Set()).add(typedKey(value)));
      }
    }
    lookups.set(list, index);
  }
  return index;
}

function position(index: Lookup, key: string): number | undefined {
  const stored = index.positions.get(key);
  if (!stored) return undefined;
  let at = stored.at;
  for (let version = stored.version; version < index.deletions.length; version++) {
    if (index.deletions[version]! < stored.at) at--;
  }
  index.positions.set(key, { at, version: index.deletions.length });
  return at;
}

/** First entry with this id (and type), as Array.find would return, indexed once per list. */
export function findRef<T extends { id: string; type: string }>(list: readonly T[], id: string, type?: string): T | undefined {
  const index = lookup(list as unknown as readonly Listed[]);
  return (type === undefined ? index.byId.get(id) : index.byKey.get(JSON.stringify([type, id]))) as T | undefined;
}

export function resourceChildren(resources: readonly Resource[], parent: Ref): Resource[] {
  const index = lookup(resources);
  return [...(index.children.get(refKey(parent)) ?? [])].map((key) => index.byKey.get(key) as Resource).filter((r) => r !== undefined);
}

const graphs = new WeakMap<readonly StoredTuple[], Graph>();
export function graphOf(tuples: readonly StoredTuple[]): Graph {
  let graph = graphs.get(tuples);
  if (!graph) { graph = indexTuples(tuples); graphs.set(tuples, graph); }
  return graph;
}

export function tuplesOn(tuples: readonly StoredTuple[], object: Ref): readonly StoredTuple[] {
  return (graphOf(tuples).byObject.get(refKey(object)) ?? []) as readonly StoredTuple[];
}

export function primeDecisionIndexes(state: RecordState): void {
  lookup(state.subjects); lookup(state.resources); lookup(state.tuples); graphOf(state.tuples);
}

function reindexById(list: readonly Listed[], index: Lookup, id: string): void {
  index.byId.delete(id);
  for (const value of list) if (value.id === id) { index.byId.set(id, value); return; }
}

function childLink(index: Lookup, value: Resource, remove: boolean): void {
  if (!value.parent) return;
  const parent = refKey(value.parent), child = typedKey(value);
  const children = index.children.get(parent);
  if (remove) {
    children?.delete(child);
    if (!children?.size) index.children.delete(parent);
  } else index.children.set(parent, (children ?? new Set()).add(child));
}

function patchList(list: Listed[], deltas: readonly RecordDelta[], tupleChanges: TupleIndexChange[]): void {
  const index = lookup(list);
  for (const delta of deltas) {
    const id = JSON.stringify(delta.kind === 'tuple' ? ['tuple', delta.id] : [delta.type, delta.id]);
    const at = position(index, id);
    const old = at === undefined ? undefined : list[at];
    if (delta.op === 'delete') {
      if (at === undefined || old === undefined) continue;
      record(list, { op: 'insert', at, old }); list.splice(at, 1); index.deletions.push(at); index.positions.delete(id); index.byKey.delete(id);
      if ('parent' in old) childLink(index, old as Resource, true);
      reindexById(list, index, delta.id);
      if (delta.kind === 'tuple') tupleChanges.push({ op: 'delete', tuple: old as StoredTuple });
    } else if (delta.value) {
      const value = delta.value as Listed;
      if (at === undefined) {
        record(list, { op: 'pop' }); index.positions.set(id, { at: list.length, version: index.deletions.length }); list.push(value);
        if (!index.byKey.has(id)) index.byKey.set(id, value);
        if (!index.byId.has(value.id)) index.byId.set(value.id, value);
      } else {
        record(list, { op: 'set', at, old: old! }); list[at] = value; index.byKey.set(id, value);
        if (index.byId.get(value.id) === old) index.byId.set(value.id, value);
        if (old && 'parent' in old && old.parent) childLink(index, old as Resource, true);
      }
      if ('parent' in value && value.parent) childLink(index, value as Resource, false);
      if (delta.kind === 'tuple') {
        if (old) tupleChanges.push({ op: 'delete', tuple: old as StoredTuple });
        tupleChanges.push({ op: 'put', tuple: value as StoredTuple });
      }
    }
  }
}

export interface PatchMark { readonly subjects: number; readonly resources: number; readonly tuples: number }
const lists = (state: RecordState): Array<readonly Listed[]> => [state.subjects, state.resources, state.tuples];
/** How far each of this state's arrays has been patched in place so far. */
export function patchMark(state: RecordState): PatchMark {
  const [subjects, resources, tuples] = lists(state).map((list) => journals.get(list)?.length ?? 0) as [number, number, number];
  return { subjects, resources, tuples };
}
/** Undoes every in-place patch of this state's arrays made after `mark`, then rebuilds their indexes (failure path only). */
export function rollbackPatches(state: RecordState, mark: PatchMark): void {
  for (const [list, length] of [[state.subjects, mark.subjects], [state.resources, mark.resources], [state.tuples, mark.tuples]] as const) {
    const journal = journals.get(list);
    if (!journal || journal.length <= length) continue;
    const values = list as Listed[];
    for (const undo of journal.splice(length).reverse()) {
      if (undo.op === 'pop') values.pop();
      else if (undo.op === 'set') values[undo.at] = undo.old;
      else values.splice(undo.at, 0, undo.old);
    }
    lookups.delete(list); graphs.delete(list as readonly StoredTuple[]);
  }
  primeDecisionIndexes(state);
}
/** A commit point: the patches so far can no longer be undone. */
export function forgetPatches(state: RecordState): void { for (const list of lists(state)) journals.delete(list); }

/** Reuses the previous arrays and their indexes for an ordinary delta; an unannotated reorder takes the full path. */
export function patchDecisionState<T extends RecordState>(previous: T, next: T, deltas: readonly RecordDelta[]): T {
  if (deltas.some((delta) => delta.move)) {
    primeDecisionIndexes(next);
    return next;
  }
  const tupleChanges: TupleIndexChange[] = [];
  for (const [kind, list] of [['subject', previous.subjects], ['resource', previous.resources], ['tuple', previous.tuples]] as const) {
    const changes = deltas.filter((delta) => delta.kind === kind);
    if (changes.length) patchList(list as Listed[], changes, tupleChanges);
  }
  if (tupleChanges.length) {
    const graph = graphs.get(previous.tuples);
    if (graph) patchTupleIndex(graph, tupleChanges);
  }
  return { ...next, subjects: previous.subjects, resources: previous.resources, tuples: previous.tuples };
}
