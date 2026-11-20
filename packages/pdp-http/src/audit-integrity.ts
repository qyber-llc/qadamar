import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import type { Anchor, AuditRecord, Head } from './audit.ts';

export interface SegmentSeal {
  version: 1;
  node: string;
  firstSeq: number;
  lastSeq: number;
  removed: number;
  prefixHash: string;
  head: Head;
  sealedAt: string;
  anchor?: Anchor;
}
export interface AuditSegment extends SegmentSeal { mac: string }
export type RetentionPlan = SegmentSeal & { rows: AuditRecord[] };

export const auditMac = (key: Buffer, value: unknown): string => createHmac('sha256', key).update(canonical(value)).digest('hex');
export const macMatches = (key: Buffer, value: unknown, mac: string): boolean => {
  if (!/^[0-9a-f]{64}$/.test(mac)) return false;
  return timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(auditMac(key, value), 'hex'));
};
export function sealSegment(key: Buffer, plan: SegmentSeal): AuditSegment {
  return { ...plan, mac: auditMac(key, plan) };
}
export function validSegment(value: unknown, key: Buffer): AuditSegment | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const { mac, ...signed } = value as AuditSegment;
  const s = signed as SegmentSeal;
  if (s.version !== 1 || typeof s.node !== 'string' || !Number.isSafeInteger(s.firstSeq) || s.firstSeq < 1 ||
    !Number.isSafeInteger(s.lastSeq) || !Number.isSafeInteger(s.removed) || s.removed !== s.lastSeq - s.firstSeq + 1 ||
    s.head?.seq !== s.lastSeq || !/^[0-9a-f]{64}$/.test(s.head?.hash ?? '') || !/^[0-9a-f]{64}$/.test(s.prefixHash) ||
    typeof s.sealedAt !== 'string' || !Number.isFinite(Date.parse(s.sealedAt)) || typeof mac !== 'string' || !macMatches(key, signed, mac)) return undefined;
  const anchored = s.anchor?.heads?.[s.node] ?? (s.anchor ? { seq: s.anchor.seq, hash: s.anchor.hash } : undefined);
  if (s.anchor && (anchored?.seq !== s.lastSeq || anchored.hash !== s.head.hash)) return undefined;
  return value as AuditSegment;
}
/** Later seals continue exactly where the previous one stopped; removed row contents are no longer needed to check this. */
export function validSegments(values: readonly unknown[], key: Buffer, node: string): AuditSegment[] | undefined {
  const segments: AuditSegment[] = [];
  let next = 1;
  for (const value of values) {
    const segment = validSegment(value, key);
    if (!segment || segment.node !== node || segment.firstSeq !== next) return undefined;
    segments.push(segment); next = segment.lastSeq + 1;
  }
  return segments;
}
export const segmentOf = (segments: readonly AuditSegment[], node: string): AuditSegment | undefined =>
  segments.filter((s) => s.node === node).at(-1);
