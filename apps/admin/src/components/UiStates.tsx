import { Fragment, useEffect, useState } from 'react';
import { ApiError } from '../api/client';
import { errorText } from '../api/errorText';
import type { Level, TraceStep } from '../api/types';
import { formatDateHuman, formatHop, LEVEL_LABELS } from '../utils/expr';
import { useLang, useT } from '../i18n';

export function LoadingState(props: { readonly label?: string }) {
  const t = useT();
  return (
    <div className="card" role="status" aria-live="polite">
      <div style={{ color: 'var(--text-muted)' }}>
        {props.label ?? t.common.loading}
      </div>
    </div>
  );
}

export function EmptyState(props: {
  readonly title: string;
  readonly detail?: string;
  readonly actionLabel?: string;
  readonly actionHref?: string;
}) {
  return (
    <div className="notice-box" role="status" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
      <div>
        <div style={{ fontWeight: 500, color: 'var(--text-primary)', marginBottom: props.detail ? '2px' : 0 }}>
          {props.title}
        </div>
        {props.detail ? <div className="metric-sub">{props.detail}</div> : null}
      </div>
      {props.actionLabel && props.actionHref ? (
        <a href={props.actionHref} className="btn btn-sm btn-primary">
          {props.actionLabel}
        </a>
      ) : null}
    </div>
  );
}

function extractDetailsList(details: unknown): string[] {
  if (!details) return [];
  if (Array.isArray(details)) {
    return details.map((item) => (typeof item === 'string' ? item : JSON.stringify(item)));
  }
  if (typeof details === 'object') {
    return Object.entries(details as Record<string, unknown>).map(
      ([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`,
    );
  }
  return [String(details)];
}

export function ErrorAlert(props: {
  readonly error: unknown;
  readonly contextTitle?: string;
  readonly onRetry?: () => void;
}) {
  const t = useT();
  const isApi = props.error instanceof ApiError;
  const deadlineMs = isApi
    ? props.error.retryDeadlineMs ??
      (props.error.retryAfter !== null ? Date.now() + props.error.retryAfter * 1000 : null)
    : null;
  const [nowMs, setNowMs] = useState(() => Date.now());

  useEffect(() => {
    if (deadlineMs === null) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => {
      const current = Date.now();
      setNowMs(current);
      if (current >= deadlineMs) {
        window.clearInterval(timer);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [deadlineMs]);

  if (!props.error) return null;

  const status = isApi ? props.error.status : null;
  const { text, detail } = errorText(t, props.error);
  const detailsList = isApi ? extractDetailsList(props.error.details) : [];
  const retryAfter =
    deadlineMs !== null ? Math.max(0, Math.ceil((deadlineMs - nowMs) / 1000)) : null;

  return (
    <div className="alert-error">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <div role="alert">
          {status ? (
            <span className="badge badge-deny" style={{ marginInlineEnd: '8px' }}>
              {status}
            </span>
          ) : null}
          <strong>{props.contextTitle ? `${props.contextTitle}: ` : ''}</strong>
          <span>{text}</span>
          {detail ? <div className="metric-sub">{t.errors.serverDetail}: <span lang="en">{detail}</span></div> : null}
        </div>
        {props.onRetry ? (
          <button type="button" className="btn btn-sm" onClick={props.onRetry}>
            {t.common.retry}
          </button>
        ) : null}
      </div>
      {retryAfter !== null ? (
        <div className="mono" role="timer" style={{ marginTop: '6px', fontSize: '12px' }}>
          {t.common.retryIn(retryAfter)}
        </div>
      ) : null}
      {detailsList.length > 0 ? (
        <ul style={{ margin: '8px 0 0 0', paddingInlineStart: '20px', fontSize: '12px' }} className="mono">
          {detailsList.map((d, idx) => (
            <li key={idx}>{d}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function LevelBadge(props: { readonly level: Level }) {
  useLang(); // re-render with the console language: LEVEL_LABELS reads it
  const cls =
    props.level === 3
      ? 'badge badge-deny'
      : props.level === 2
        ? 'badge badge-warn'
        : props.level === 1
          ? 'badge'
          : 'badge badge-allow';
  return <span className={cls}>{LEVEL_LABELS[props.level] ?? `L${props.level}`}</span>;
}

export function DecisionBadge(props: {
  readonly decision: boolean;
  readonly wouldDeny?: readonly string[];
}) {
  const t = useT();
  if (!props.decision) {
    return <span className="badge badge-deny">{t.common.deny}</span>;
  }
  if (props.wouldDeny && props.wouldDeny.length > 0) {
    return <span className="badge badge-would-deny">{t.common.wouldDeny}</span>;
  }
  return <span className="badge badge-allow">{t.common.allow}</span>;
}

export function OutcomeBadge(props: { readonly outcome: TraceStep['outcome'] }) {
  const t = useT();
  switch (props.outcome) {
    case 'pass':
      return <span className="badge badge-allow">{t.common.pass}</span>;
    case 'deny':
      return <span className="badge badge-deny">{t.common.deny}</span>;
    case 'would_deny':
      return <span className="badge badge-would-deny">{t.common.wouldDeny}</span>;
    case 'obligation':
      return <span className="badge badge-warn">{t.common.obligation}</span>;
    case 'skip':
      return <span className="badge badge-lock">{t.common.skip}</span>;
  }
}

export function DateText(props: { readonly iso: string | undefined | null }) {
  useLang(); // re-render with the console language: formatDateHuman reads it
  if (!props.iso) return <span>—</span>;
  return <span title={props.iso}>{formatDateHuman(props.iso)}</span>;
}

export function RelationPathChain(props: { readonly path: readonly string[] | undefined }) {
  const t = useT();
  if (!props.path || props.path.length === 0) return null;
  const hops = props.path.flatMap((entry) =>
    entry.includes(' -> ') ? entry.split(' -> ').map((s) => s.trim()) : [entry],
  );
  return (
    <span className="hop-chain" role="group" aria-label={t.common.relationPath}>
      {hops.map((hop, idx) => (
        <Fragment key={`${hop}-${idx}`}>
          {idx > 0 ? <span className="hop-arrow" aria-hidden="true">→</span> : null}
          <span className="hop-item">{formatHop(hop)}</span>
        </Fragment>
      ))}
    </span>
  );
}
