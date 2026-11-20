// ABAC on content attributes (mask, redact, deny): the rules of the bundle field abacContent. The legacy field cbac
// (content rules before CBAC came to mean context-based access control) is read for one version, then removed.
import type { AbacContentRule, PolicyBundle } from './types.ts';

/** validateBundle refuses both fields at once; a bundle that skipped it still loses no rule (fail closed). */
export function contentRules(bundle: PolicyBundle): readonly AbacContentRule[] {
  if (!bundle.cbac) return bundle.abacContent ?? [];
  return bundle.abacContent ? [...bundle.abacContent, ...bundle.cbac] : bundle.cbac;
}
