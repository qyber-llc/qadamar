import { canonical, check, contentRules, contextRuleSelected, indexTuples, keyOf, principals, procedureFingerprint, rbacGrant } from '../../../core/src/index.ts';
import type {
  AbacContentRule, AbacRule, ContextRule, Graph, ImpactAnalysis, ImpactCell, PolicyBundle, Ref, RelationDef, Resource,
  SodRule, Tuple, World,
} from '../../../core/src/index.ts';
import type { Certification } from '../store.ts';

export class AffectedSetLimit extends Error {}

interface RulePair<T> { readonly before?: T; readonly after?: T }
type Query = { readonly object: Ref; readonly relation: string; readonly subject: Ref };

const refKey = (ref: Ref): string => keyOf(ref);
const cellKey = (cell: ImpactCell): string => JSON.stringify([cell.subject.type, cell.subject.id, cell.resource.type, cell.resource.id, cell.action]);
const different = (a: unknown, b: unknown): boolean => a !== b && canonical(a) !== canonical(b);
const own = (value: object, key: string): boolean => Object.hasOwn(value, key);

function unionRefs<T extends Ref>(before: readonly T[], after: readonly T[]): Map<string, T> {
  const out = new Map<string, T>();
  for (const value of [...before, ...after]) if (!out.has(refKey(value))) out.set(refKey(value), value);
  return out;
}

function changedById<T extends { readonly id: string }>(before: readonly T[], after: readonly T[]): RulePair<T>[] {
  const b = new Map(before.map((rule) => [rule.id, rule])); const a = new Map(after.map((rule) => [rule.id, rule]));
  return [...new Set([...b.keys(), ...a.keys()])].filter((id) => different(b.get(id), a.get(id)))
    .map((id) => ({ before: b.get(id), after: a.get(id) }));
}

function relationSchema(bundle: PolicyBundle): unknown {
  return {
    resources: Object.fromEntries(Object.entries(bundle.schema.resourceTypes).map(([type, def]) => [type, def.relations ?? null])),
    subjects: bundle.schema.subjectRelations ?? null,
  };
}

function relations(bundle: PolicyBundle): Array<{ type: string; relation: string; def: RelationDef }> {
  const out: Array<{ type: string; relation: string; def: RelationDef }> = [];
  for (const [type, def] of Object.entries(bundle.schema.resourceTypes)) {
    for (const [relation, relationDef] of Object.entries(def.relations ?? {})) out.push({ type, relation, def: relationDef });
  }
  for (const [type, defs] of Object.entries(bundle.schema.subjectRelations ?? {})) {
    for (const [relation, def] of Object.entries(defs)) out.push({ type, relation, def });
  }
  return out;
}

export function affectedImpact(
  before: World,
  after: World,
  now: string,
  beforeCertifications: readonly Certification[] = [],
  afterCertifications: readonly Certification[] = [],
  maximumCells = Number.MAX_SAFE_INTEGER,
): { cells: ImpactCell[]; analysis: ImpactAnalysis } {
  const subjects = unionRefs(before.subjects, after.subjects);
  const resources = unionRefs(before.resources, after.resources);
  const oldSubjects = unionRefs(before.subjects, []); const newSubjects = unionRefs(after.subjects, []);
  const oldResources = unionRefs(before.resources, []); const newResources = unionRefs(after.resources, []);
  const graphs = { before: indexTuples(before.tuples), after: indexTuples(after.tuples) };
  const cells = new Map<string, ImpactCell>(); const reasons = new Set<string>();
  const types = [...new Set([...Object.keys(before.bundle.schema.resourceTypes), ...Object.keys(after.bundle.schema.resourceTypes)])];
  const allSubjects = [...subjects.values()]; const allResources = [...resources.values()];
  const actions = (type: string): string[] => [...new Set([
    ...Object.keys(before.bundle.schema.resourceTypes[type]?.actions ?? {}),
    ...Object.keys(after.bundle.schema.resourceTypes[type]?.actions ?? {}),
  ])];
  const declared = (type: string, action: string): boolean =>
    own(before.bundle.schema.resourceTypes[type]?.actions ?? {}, action) || own(after.bundle.schema.resourceTypes[type]?.actions ?? {}, action);
  const add = (subject: Ref, resource: Ref, action: string): void => {
    if (!declared(resource.type, action)) return;
    const cell = { subject: subjects.get(refKey(subject)) ?? subject, resource: resources.get(refKey(resource)) ?? resource, action };
    const key = cellKey(cell);
    if (cells.has(key)) return;
    if (cells.size >= maximumCells) throw new AffectedSetLimit();
    cells.set(key, cell);
  };
  const addScope = (who: readonly Ref[], items: readonly Resource[], selected?: readonly string[]): void => {
    for (const resource of items) for (const subject of who) {
      for (const action of selected ?? actions(resource.type)) if (declared(resource.type, action)) add(subject, resource, action);
    }
  };
  const ofTypes = (selected: readonly string[]): Resource[] => allResources.filter((resource) => selected.includes(resource.type));
  const protectedTypes = (): string[] => [...new Set([...Object.keys(before.bundle.needToKnow.protect), ...Object.keys(after.bundle.needToKnow.protect)])];
  const addProtected = (): void => addScope(allSubjects, ofTypes(protectedTypes()));

  let subjectsChanged = false;
  for (const [key, subject] of subjects) {
    const old = oldSubjects.get(key); const next = newSubjects.get(key);
    if (!different(old, next)) continue;
    subjectsChanged = true; addScope([subject], allResources);
  }
  if (subjectsChanged) reasons.add('changed, added, or removed subjects');

  for (const [key, resource] of resources) {
    const old = oldResources.get(key); const next = newResources.get(key);
    if (!different(old, next)) continue;
    reasons.add('changed, added, or removed resources');
    const versionOnly = old && next && canonical({ ...old, version: 0 }) === canonical({ ...next, version: 0 });
    const selected = versionOnly ? actions(resource.type).filter((action) =>
      before.bundle.schema.resourceTypes[resource.type]?.actions[action]?.certified || after.bundle.schema.resourceTypes[resource.type]?.actions[action]?.certified) : undefined;
    addScope(allSubjects, [resource], selected);
  }

  if (different(before.bundle, after.bundle)) {
    if (different(before.bundle.mandatory, after.bundle.mandatory)) {
      reasons.add('mandatory-model policy changed'); addScope(allSubjects, allResources);
    }
    if (different(before.bundle.needToKnow, after.bundle.needToKnow) || different(relationSchema(before.bundle), relationSchema(after.bundle))) {
      reasons.add('need-to-know or relation policy changed'); addProtected();
    }

    for (const type of types) {
      const old = before.bundle.schema.resourceTypes[type]; const next = after.bundle.schema.resourceTypes[type];
      if (old?.constrained !== next?.constrained) {
        reasons.add(`constrained resource type ${type} changed`); addScope(allSubjects, ofTypes([type]));
      }
      for (const action of actions(type)) {
        if (different(old?.actions[action], next?.actions[action])) {
          reasons.add(`action definition ${type}:${action} changed`); addScope(allSubjects, ofTypes([type]), [action]);
        }
      }
    }

    if (different(before.bundle.rbac, after.bundle.rbac)) {
      reasons.add('RBAC grants changed');
      for (const subject of allSubjects) for (const type of types) for (const action of actions(type)) {
        const old = rbacGrant(before.bundle, subject, type, action) !== null;
        const next = rbacGrant(after.bundle, subject, type, action) !== null;
        // a time-bounded role assignment may be live at the decision time and not now: always in scope (conservative)
        if (old !== next || subject.roleAssignments?.length) addScope([subject], ofTypes([type]), [action]);
      }
    }

    const abac = changedById<AbacRule>(before.bundle.abac, after.bundle.abac);
    for (const { before: old, after: next } of abac) {
      const rule = old ?? next!;
      reasons.add(`ABAC rule ${rule.id} changed`);
      const selectedTypes = old && next
        ? [...new Set([...(old.resourceTypes ?? types), ...(next.resourceTypes ?? types)])]
        : (old?.resourceTypes ?? next?.resourceTypes ?? types);
      for (const type of selectedTypes) {
        const selected = old && next
          ? actions(type).filter((action) => (!old.actions || old.actions.includes(action)) || (!next.actions || next.actions.includes(action)))
          : (old?.actions ?? next?.actions ?? actions(type));
        addScope(allSubjects, ofTypes([type]), selected);
      }
    }

    for (const { before: old, after: next } of changedById<AbacContentRule>(contentRules(before.bundle), contentRules(after.bundle))) {
      const rule = old ?? next!;
      reasons.add(`ABAC content rule ${rule.id} changed`);
      const classes = [...new Set([...(old ? [old.contentClass] : []), ...(next ? [next.contentClass] : [])])];
      const items = allResources.filter((resource) => classes.some((name) => resource.contentClasses?.includes(name)));
      const selected = old && next && old.actions && next.actions ? [...new Set([...old.actions, ...next.actions])]
        : old && next ? undefined : (old?.actions ?? next?.actions);
      addScope(allSubjects, items, selected);
    }

    for (const { before: old, after: next } of changedById<ContextRule>(before.bundle.context ?? [], after.bundle.context ?? [])) {
      const rule = old ?? next!;
      reasons.add(`context rule ${rule.id} changed`);
      const selectedTypes = [...new Set(old && next ? [...(old.resourceTypes ?? types), ...(next.resourceTypes ?? types)] : (old?.resourceTypes ?? next?.resourceTypes ?? types))];
      for (const type of selectedTypes) {
        const selected = actions(type).filter((action) => {
          const kind = before.bundle.schema.resourceTypes[type]?.actions[action]?.kind ?? after.bundle.schema.resourceTypes[type]?.actions[action]?.kind;
          return kind !== undefined && [old, next].some((candidate) => candidate && contextRuleSelected(candidate, type, action, kind));
        });
        const items = ofTypes([type]).filter((resource) => [old, next].some((candidate) => candidate &&
          (candidate.minResourceLevel === undefined || resource.level >= candidate.minResourceLevel) &&
          (!candidate.contentClasses || candidate.contentClasses.some((name) => resource.contentClasses?.includes(name)))));
        addScope(allSubjects, items, selected);
      }
    }

    const sod = changedById<SodRule>(before.bundle.sod, after.bundle.sod);
    for (const { before: old, after: next } of sod) {
      const rule = old ?? next!;
      reasons.add(`separation-of-duty rule ${rule.id} changed`);
      addScope(allSubjects, allResources, [...new Set([...(old?.conflicting ?? []), ...(next?.conflicting ?? [])])]);
    }

    const cw = (bundle: PolicyBundle): PolicyBundle['clarkWilson'] => bundle.clarkWilson;
    if (cw(before.bundle).tokenTtlSeconds !== cw(after.bundle).tokenTtlSeconds) {
      reasons.add('decision-token lifetime changed');
      for (const type of types) addScope(allSubjects, ofTypes([type]), actions(type).filter((action) =>
        before.bundle.schema.resourceTypes[type]?.actions[action]?.certified || after.bundle.schema.resourceTypes[type]?.actions[action]?.certified));
    }
    for (const { before: old, after: next } of changedById(before.bundle.clarkWilson.ivps ?? [], after.bundle.clarkWilson.ivps ?? [])) {
      const rule = old ?? next!;
      reasons.add(`integrity verification ${rule.id} changed`);
      for (const type of [...new Set([...(old?.resourceTypes ?? []), ...(next?.resourceTypes ?? [])])]) {
        addScope(allSubjects, ofTypes([type]), actions(type).filter((action) =>
          before.bundle.schema.resourceTypes[type]?.actions[action]?.certified || after.bundle.schema.resourceTypes[type]?.actions[action]?.certified));
      }
    }
    for (const { before: old, after: next } of changedById(before.bundle.clarkWilson.inputValidators ?? [], after.bundle.clarkWilson.inputValidators ?? [])) {
      const rule = old ?? next!;
      reasons.add(`input validator ${rule.id} changed`);
      for (const type of [...new Set([...(old?.resourceTypes ?? []), ...(next?.resourceTypes ?? [])])]) {
        addScope(allSubjects, ofTypes([type]), [...new Set([...(old?.actions ?? []), ...(next?.actions ?? [])])].filter((action) =>
          before.bundle.schema.resourceTypes[type]?.actions[action]?.certified || after.bundle.schema.resourceTypes[type]?.actions[action]?.certified));
      }
    }
    for (const field of ['requireCertification', 'requirePepBinding'] as const) {
      const old = before.bundle.clarkWilson[field] ?? []; const next = after.bundle.clarkWilson[field] ?? [];
      if (!different(old, next)) continue;
      reasons.add(`${field} changed`);
      for (const type of [...new Set([...old, ...next])]) addScope(allSubjects, ofTypes([type]), actions(type).filter((action) =>
        before.bundle.schema.resourceTypes[type]?.actions[action]?.certified || after.bundle.schema.resourceTypes[type]?.actions[action]?.certified));
    }
  }

  if (different(beforeCertifications, afterCertifications)) {
    reasons.add('certification records changed');
    for (const record of [...beforeCertifications, ...afterCertifications]) {
      addScope(allSubjects, ofTypes([record.resourceType]), [record.action]);
    }
  }
  for (const record of beforeCertifications) {
    const changed = record.fingerprint === undefined ? different(before.bundle, after.bundle)
      : procedureFingerprint(before.bundle, record.resourceType, record.action) !== procedureFingerprint(after.bundle, record.resourceType, record.action);
    if (changed) {
      reasons.add(`certified procedure ${record.resourceType}:${record.action} changed`);
      addScope(allSubjects, ofTypes([record.resourceType]), [record.action]);
    }
  }

  const tuplesBefore = new Map(before.tuples.map((tuple, index) => [String((tuple as Tuple & { id?: string }).id ?? index), tuple]));
  const tuplesAfter = new Map(after.tuples.map((tuple, index) => [String((tuple as Tuple & { id?: string }).id ?? index), tuple]));
  const tupleIds = [...new Set([...tuplesBefore.keys(), ...tuplesAfter.keys()])];
  const changedTuples = tupleIds.filter((id) => different(tuplesBefore.get(id), tuplesAfter.get(id)))
    .flatMap((id) => { const old = tuplesBefore.get(id); const next = tuplesAfter.get(id); return [...(old ? [old] : []), ...(next ? [next] : [])]; });
  if (changedTuples.length) reasons.add('relation tuples changed');

  const queries = new Map<string, Query>(); const pending: Query[] = [];
  const addQuery = (query: Query): void => {
    const key = JSON.stringify([query.object.type, query.object.id, query.relation, query.subject.type, query.subject.id]);
    if (queries.has(key)) return;
    queries.set(key, query); pending.push(query);
  };
  const relationResult = (world: World, graph: Graph, object: Ref, relation: string, subject: Ref) =>
    check(world.bundle, graph, object, relation, subject, now);
  const members = (object: Ref, relation: string): Ref[] => allSubjects.filter((subject) =>
    relationResult(before, graphs.before, object, relation, subject).ok || relationResult(after, graphs.after, object, relation, subject).ok);
  const managerRelations = new Set([...relations(before.bundle), ...relations(after.bundle)].flatMap((item) =>
    item.def.union.flatMap((rewrite) => 'viaReports' in rewrite ? [rewrite.viaReports.managerRelation] : [])));
  const managers = (report: Ref, relation: string): Ref[] => {
    const out = new Map<string, Ref>(); let frontier = [report]; const seen = new Set<string>([refKey(report)]);
    for (let depth = 0; depth < 50 && frontier.length; depth++) {
      const next: Ref[] = [];
      for (const person of frontier) for (const graph of [graphs.before, graphs.after]) {
        for (const tuple of graph.byObject.get(refKey(person)) ?? []) {
          if (tuple.relation !== relation || tuple.subjectRelation) continue;
          if (seen.has(refKey(tuple.subject))) continue;
          seen.add(refKey(tuple.subject)); out.set(refKey(tuple.subject), tuple.subject); next.push(tuple.subject);
        }
      }
      frontier = next;
    }
    return [...out.values()];
  };

  for (const tuple of changedTuples) {
    if (managerRelations.has(tuple.relation)) {
      reasons.add('reporting-line tuple changed'); addProtected();
    }
    if (tuple.subjectRelation) {
      for (const subject of members(tuple.subject, tuple.subjectRelation)) addQuery({ object: tuple.object, relation: tuple.relation, subject });
    } else {
      addQuery({ object: tuple.object, relation: tuple.relation, subject: tuple.subject });
    }
    for (const bundle of [before.bundle, after.bundle]) for (const item of relations(bundle)) {
      for (const rewrite of item.def.union) {
        if ('fromParent' in rewrite && item.type === tuple.object.type && rewrite.fromParent.relation === tuple.relation) {
          for (const subject of members(tuple.subject, rewrite.fromParent.then)) addQuery({ object: tuple.object, relation: item.relation, subject });
        }
      }
    }
  }

  for (let index = 0; index < pending.length; index++) {
    const query = pending[index]!;
    for (const [world, graph] of [[before, graphs.before], [after, graphs.after]] as const) {
      for (const tuple of graph.bySubject.get(refKey(query.object)) ?? []) {
        if (tuple.subjectRelation === query.relation) addQuery({ object: tuple.object, relation: tuple.relation, subject: query.subject });
      }
      for (const item of relations(world.bundle)) {
        for (const rewrite of item.def.union) {
          if ('computed' in rewrite && item.type === query.object.type && rewrite.computed === query.relation) {
            addQuery({ object: query.object, relation: item.relation, subject: query.subject });
          } else if ('fromParent' in rewrite && rewrite.fromParent.then === query.relation) {
            for (const tuple of graph.bySubject.get(refKey(query.object)) ?? []) {
              if (tuple.relation === rewrite.fromParent.relation && tuple.object.type === item.type) {
                addQuery({ object: tuple.object, relation: item.relation, subject: query.subject });
              }
            }
          } else if ('viaReports' in rewrite && item.type === query.object.type && rewrite.viaReports.then === query.relation) {
            for (const manager of managers(query.subject, rewrite.viaReports.managerRelation)) {
              addQuery({ object: query.object, relation: item.relation, subject: manager });
            }
          }
        }
      }
    }
  }

  for (const query of queries.values()) {
    const resource = resources.get(refKey(query.object));
    if (!resource) continue;
    const applies = [before, after].some((world) => world.bundle.needToKnow.protect[resource.type]?.relation === query.relation);
    if (!applies) continue;
    for (const subject of allSubjects.filter((candidate) => principals(candidate).some((person) => refKey(person) === refKey(query.subject)))) {
      const changed = principals(subject).some((person) => {
        const old = relationResult(before, graphs.before, query.object, query.relation, person);
        const next = relationResult(after, graphs.after, query.object, query.relation, person);
        return old.ok !== next.ok || old.breakGlass !== next.breakGlass;
      });
      if (changed) addScope([subject], [resource]);
    }
  }

  if (!reasons.size) reasons.add('no decision or obligation inputs changed');
  return { cells: [...cells.values()], analysis: { affectedCells: cells.size, reasons: [...reasons].sort() } };
}
