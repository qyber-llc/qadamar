import { useEffect, useState, useCallback, useRef } from 'react';
import { api, ApiError, getServerNowMs } from '../api/client';
import { errorText } from '../api/errorText';
import type { BreakGlassListResponse, ChangeRecord, InboxResponse, SessionUser } from '../api/types';
import { ConfirmDialog } from '../components/ConfirmDialog';
import type { ExplainTarget } from '../components/ExplainDrawer';
import { ImpactTables } from '../components/ImpactTables';
import { EmptyState, ErrorAlert, LoadingState, DateText } from '../components/UiStates';
import { useT } from '../i18n';
import { ltr } from '../i18n/shape';
import { canDecideChange, canOpenBreakGlass, canProposeAnyChange, canUseSimulator } from '../utils/permissions';
import { awaitsUser, BULK_MAX, buildQueue, changeKey, dayAfter, decisionBlocks, emergenciesAwaiting, inboxKey, INBOX_TABS, SNOOZE_MAX_DAYS, type DecisionBlock, type InboxTab } from '../utils/inbox';
import '../styles/operations.css';
import { buildHref } from '../utils/router';
import { InvalidatedCertifications } from './IntegrityCards';
import { ApprovalQueue } from './ApprovalQueue';
import { ChangeLevel, changeLabel, statusLabel } from './approvalLabels';

export { decisionBlocks, type DecisionBlock } from '../utils/inbox';

export function selectActiveChange(changes: readonly ChangeRecord[], selectedId: string): ChangeRecord | null {
  return selectedId ? (changes.find((c) => c.id === selectedId) ?? null) : (changes[0] ?? null);
}

const NO_INBOX: InboxResponse = { approvalMode: 'individual', snoozes: [] };

export function ApprovalsScreen(props: {
  readonly user: SessionUser;
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
  readonly onExplain?: (target: ExplainTarget) => void;
  readonly onApprovalChanged: () => void;
}) {
  const t = useT();
  const a = t.approvals;
  const tab: InboxTab = (INBOX_TABS as readonly string[]).includes(props.params.status ?? '') ? props.params.status as InboxTab : 'awaiting';
  const selectedId = props.params.id ?? '';

  const [changes, setChanges] = useState<readonly ChangeRecord[]>([]);
  const [emergencies, setEmergencies] = useState<BreakGlassListResponse | null>(null);
  const [inbox, setInbox] = useState<InboxResponse>(NO_INBOX);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const reqGenRef = useRef(0);

  const [decisionReason, setDecisionReason] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [staleConflict, setStaleConflict] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const [cursor, setCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [failures, setFailures] = useState<ReadonlyMap<string, string>>(new Map());
  const [bulkNote, setBulkNote] = useState('');
  const [bulkConfirm, setBulkConfirm] = useState<'approve' | 'reject' | null>(null);
  const [snoozeFor, setSnoozeFor] = useState<string | null>(null);
  const [snoozeDate, setSnoozeDate] = useState('');
  const rows = useRef(new Map<string, HTMLElement>());
  const noteRef = useRef<HTMLInputElement>(null);
  const bulkNoteRef = useRef<HTMLInputElement>(null);
  const snoozeRef = useRef<HTMLInputElement>(null);
  const [focusTarget, setFocusTarget] = useState<{ readonly ref: 'note' | 'bulk' | 'snooze'; readonly tick: number } | null>(null);

  const showEmergencies = canOpenBreakGlass(props.user.roles);
  const loadChanges = useCallback(async () => {
    const gen = ++reqGenRef.current;
    setLoading(true);
    setError(null);
    try {
      const [res, mine, bg] = await Promise.all([
        api.getChanges(), api.getInbox(),
        showEmergencies ? api.getBreakGlass().catch(() => null) : Promise.resolve(null),
      ]);
      if (reqGenRef.current !== gen) return;
      setChanges(res.items);
      setInbox(mine);
      setEmergencies(bg);
      if (mine.approvalMode !== 'list') setSelected(new Set());
    } catch (err) {
      if (reqGenRef.current !== gen) return;
      setError(err);
    } finally {
      if (reqGenRef.current === gen) setLoading(false);
    }
  }, [showEmergencies]);

  useEffect(() => {
    void loadChanges();
  }, [loadChanges]);

  const listMode = inbox.approvalMode === 'list';
  const snoozedUntil = new Map(inbox.snoozes.map((s) => [s.item, s.until]));
  const queue = buildQueue(tab, changes, emergenciesAwaiting(emergencies, props.user), new Set(snoozedUntil.keys()), props.user);
  const queueChanges = queue.flatMap((item) => item.kind === 'change' ? [item.change] : []);
  const activeChange = selectedId ? selectActiveChange(changes, selectedId) : (queueChanges[0] ?? null);
  const cursorKey = cursor && queue.some((item) => item.key === cursor) ? cursor : queue[0]?.key ?? null;
  const selectableIds = queueChanges.filter((c) => awaitsUser(c, props.user)).map((c) => c.id);

  const clearDecision = () => {
    setStaleConflict(null);
    setActionError(null);
    setDecisionReason('');
  };
  const selectChange = (id: string) => {
    clearDecision();
    props.setParams({ id });
  };
  /** Adds `ids` (or toggles a single one), never past the cap. */
  const toggle = (ids: readonly string[], add?: boolean) => {
    const next = new Set(selected);
    for (const id of ids) {
      const on = add ?? !next.has(id);
      if (on && !next.has(id) && next.size >= BULK_MAX) { setFeedback(a.selectCap(BULK_MAX)); break; }
      if (on) next.add(id); else next.delete(id);
    }
    setSelected(next);
  };
  const selectAll = () => {
    setSelected(new Set(selectableIds.slice(0, BULK_MAX)));
    if (selectableIds.length > BULK_MAX) setFeedback(a.selectCap(BULK_MAX));
  };
  const openSnooze = (key: string) => {
    setSnoozeFor(key);
    setSnoozeDate(dayAfter(getServerNowMs(), 1));
    setFocusTarget({ ref: 'snooze', tick: Date.now() });
  };

  useEffect(() => {
    const target = focusTarget?.ref === 'note' ? noteRef : focusTarget?.ref === 'bulk' ? bulkNoteRef : focusTarget ? snoozeRef : null;
    target?.current?.focus();
  }, [focusTarget]);

  // the latest render's handler, so the listener added once never reads stale state
  const onKey = useRef<(e: KeyboardEvent) => void>(() => undefined);
  onKey.current = (e: KeyboardEvent) => {
    if (document.querySelector('[aria-modal="true"]')) return;
    const action = inboxKey({ key: e.key, shiftKey: e.shiftKey, ctrlKey: e.ctrlKey, metaKey: e.metaKey, altKey: e.altKey, target: e.target as HTMLElement | null }, listMode);
    if (!action || queue.length === 0) return;
    const index = Math.max(0, queue.findIndex((item) => item.key === cursorKey));
    const current = queue[index]!;
    e.preventDefault();
    if (action.type === 'move') {
      const next = queue[Math.min(queue.length - 1, Math.max(0, index + action.delta))]!;
      if (action.extend) toggle([current, next].flatMap((item) => item.kind === 'change' && awaitsUser(item.change, props.user) ? [item.change.id] : []), true);
      setCursor(next.key);
      rows.current.get(next.key)?.focus();
      return;
    }
    if (action.type === 'toggle') { if (current.kind === 'change' && awaitsUser(current.change, props.user)) toggle([current.change.id]); return; }
    if (action.type === 'snooze') { openSnooze(current.key); return; }
    if (current.kind === 'emergency') { window.location.hash = buildHref('break-glass'); return; }
    selectChange(current.change.id);
    if (action.type === 'primary') setFocusTarget({ ref: listMode && selected.size > 0 ? 'bulk' : 'note', tick: Date.now() });
  };
  useEffect(() => {
    const listener = (e: KeyboardEvent) => onKey.current(e);
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, []);

  const handleDecision = async (decision: 'approve' | 'reject') => {
    if (!activeChange) return;
    const refused = decisionBlocks(activeChange, props.user);
    if (refused.both || (decision === 'approve' && refused.approve)) return;
    const reasonText = decisionReason.trim();
    if (!reasonText) return;
    setSubmitting(true);
    setActionError(null);
    setStaleConflict(null);
    setFeedback(null);
    try {
      const updated =
        decision === 'approve'
          ? await api.approveChange(activeChange.id, reasonText)
          : await api.rejectChange(activeChange.id, reasonText);
      setFeedback(a.feedback(changeLabel(updated), statusLabel(updated.status)));
      setDecisionReason('');
      props.onApprovalChanged();
      await loadChanges();
    } catch (err) {
      if (err instanceof ApiError && (err.status === 409 || err.code === 'stale')) {
        setStaleConflict(err.code === 'stale' ? a.staleDetail : errorText(t, err).text);
      } else {
        setActionError(err);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const runBulk = async (approve: boolean) => {
    setBulkConfirm(null);
    const ids = [...selected];
    const note = bulkNote.trim();
    if (!ids.length || !note) return;
    setSubmitting(true);
    setActionError(null);
    setFeedback(null);
    try {
      const res = await api.decideChanges(ids, approve, note);
      const failed = res.results.filter((r) => !r.ok);
      const codes: Readonly<Record<string, string>> = t.errors.codes;
      // the reason in the console language; the server's own message (isolated, it is English) for a code it does not know
      setFailures(new Map(failed.map((r) => [r.id, (r.error && Object.hasOwn(codes, r.error) ? codes[r.error] : undefined) ?? ltr(r.message ?? r.error ?? '')])));
      setSelected(new Set(failed.map((r) => r.id))); // what was refused stays selected, with its reason
      setFeedback(a.bulkSummary(res.results.length - failed.length, failed.length));
      if (!failed.length) setBulkNote('');
      props.onApprovalChanged();
      await loadChanges();
    } catch (err) {
      if (err instanceof ApiError && err.code === 'individual_mode') await loadChanges();
      setActionError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const runSnooze = async (key: string, until: string | null) => {
    setSubmitting(true);
    setActionError(null);
    try {
      if (until) await api.snooze(key, until); else await api.unsnooze(key);
      setSnoozeFor(null);
      setFeedback(until ? a.snoozedNotice(until) : a.unsnoozedNotice);
      await loadChanges();
    } catch (err) {
      setActionError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const userCanDecide = canDecideChange(props.user.roles);
  const canPropose = canProposeAnyChange(props.user.roles);
  const canExplain = canUseSimulator(props.user.roles) ? props.onExplain : undefined;
  const isSelfMaker = activeChange ? activeChange.makerId === props.user.id : false;
  const blocks = activeChange ? decisionBlocks(activeChange, props.user) : {};
  const approveBlock = blocks.both ?? blocks.approve;
  const blockText = (block: DecisionBlock): string => block === 'selfMaker' ? a.cannotApproveOwn : a.blocked[block];
  const hasReason = decisionReason.trim().length > 0;
  const bulkReady = selected.size > 0 && bulkNote.trim().length > 0 && !submitting;
  const tabLabel = (st: InboxTab): string => st === 'awaiting' ? a.awaitingTab : st === 'snoozed' ? a.snoozedTab : a[st];

  return (
    <section className="operations-screen" aria-labelledby="title-approvals">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-approvals">{a.title}</h1>
          <p className="screen-subtitle">
            {a.subtitle}
          </p>
        </div>
        {userCanDecide ? <span className="badge">{listMode ? a.modeList : a.modeIndividual}</span> : null}
      </div>

      <div className="tab-bar" role="tablist" aria-label={a.statusFilter}>
        {INBOX_TABS.map((st) => (
          <button
            key={st}
            type="button"
            role="tab"
            className="tab-btn"
            aria-selected={tab === st}
            onClick={() => {
              clearDecision();
              setCursor(null);
              setSelected(new Set()); // never decide what the new tab does not show
              setFailures(new Map());
              props.setParams({ status: st, id: undefined });
            }}
          >
            {tabLabel(st)}
          </button>
        ))}
      </div>
      <p className="operations-meta" id="approvals-keys">{listMode ? a.keysList : a.keysIndividual}</p>

      {loading ? <LoadingState label={a.loading} /> : null}
      {error ? <ErrorAlert error={error} contextTitle={a.loadError} onRetry={() => void loadChanges()} /> : null}
      {feedback ? <div className="alert-success" role="status" aria-live="polite">{feedback}</div> : null}
      {actionError && !activeChange ? <ErrorAlert error={actionError} contextTitle={a.decisionFailed} /> : null}

      {snoozeFor ? (
        <div className="notice-box">
          <div className="form-row" style={{ marginBottom: 0 }}>
            <div className="form-group">
              <label htmlFor="approval-snooze-until">{a.snoozeUntil}</label>
              <input ref={snoozeRef} id="approval-snooze-until" type="date" value={snoozeDate} min={dayAfter(getServerNowMs(), 1)}
                max={dayAfter(getServerNowMs(), SNOOZE_MAX_DAYS)} aria-describedby="approval-snooze-help" onChange={(e) => setSnoozeDate(e.target.value)} />
            </div>
            <button type="button" className="btn btn-primary" disabled={submitting || !snoozeDate} onClick={() => void runSnooze(snoozeFor, snoozeDate)}>{a.snooze}</button>
            <button type="button" className="btn" onClick={() => setSnoozeFor(null)}>{t.common.cancel}</button>
          </div>
          <p className="operations-meta" id="approval-snooze-help">{a.snoozeHelp(SNOOZE_MAX_DAYS)}</p>
        </div>
      ) : null}

      {!loading && !error && queue.length === 0 && !activeChange ? (
        <EmptyState
          title={tab === 'awaiting' ? a.emptyAwaiting : tab === 'snoozed' ? a.emptySnoozed : a.empty}
          actionLabel={canPropose ? a.openSimulator : undefined}
          actionHref={canPropose ? buildHref('simulator', { mode: 'impact' }) : undefined}
        />
      ) : null}

      {!loading && !error && (queue.length > 0 || activeChange) ? (
        <div>
          {activeChange ? (
            <div className="card operations-approval-detail">
              <p className="operations-label">{activeChange.status === 'pending' ? userCanDecide && !isSelfMaker ? a.awaitingYou : a.awaitingSecond : a.decisionRecord}</p>
              <h2 className="card-title" title={`${changeLabel(activeChange)} · ${activeChange.id}`}>
                <span>{changeLabel(activeChange)}</span>
                <ChangeLevel change={activeChange} />
              </h2>
              <p className="operations-meta mono" title={activeChange.stateDigest}>{a.stateDigest(activeChange.stateDigest.slice(0, 12))}</p>

              <div className="notice-box">
                <div className="operations-meta">
                  <span>{a.proposedBy}</span> <span className="mono">{activeChange.makerId}</span> · <span>{a.created}</span> <DateText iso={activeChange.createdAt} />
                  {activeChange.checkerId ? (
                    <> · <span>{a.reviewedBy}</span> <span className="mono">{activeChange.checkerId}</span> (<DateText iso={activeChange.decidedAt} />)</>
                  ) : null}
                </div>
                <div title={activeChange.reason} style={{ marginTop: '6px' }}><strong>{a.reason}</strong> {activeChange.reason}</div>
                {activeChange.decisionReason ? <div title={activeChange.decisionReason} style={{ marginTop: '4px' }}><strong>{a.reviewNote}</strong> {activeChange.decisionReason}</div> : null}
              </div>

              {activeChange.warnings?.length ? (
                <div className="alert-warn" role="status" style={{ marginTop: '12px' }}>
                  {activeChange.warnings.map((w) => <div key={w} className="mono">{w}</div>)}
                </div>
              ) : null}
              <InvalidatedCertifications items={activeChange.invalidatesCertifications} />
              <ImpactTables impact={activeChange.impact} onExplain={canExplain} />

              {staleConflict ? (
                <div className="alert-warn" role="alert" style={{ marginTop: '16px' }}>
                  <div style={{ fontWeight: 600, marginBottom: '4px' }}>{a.staleTitle}</div>
                  <div style={{ marginBottom: '8px' }}>{staleConflict}</div>
                  <a href={buildHref('simulator', { mode: 'impact', kind: activeChange.kind })} className="btn btn-sm btn-primary">
                    {a.resimulate}
                  </a>
                </div>
              ) : null}

              {actionError ? <ErrorAlert error={actionError} contextTitle={a.decisionFailed} /> : null}

              {activeChange.status === 'pending' ? (
                <div className="notice-box" style={{ marginTop: '16px', marginBottom: 0 }}>
                  {isSelfMaker ? (
                    <div className="alert-error" role="status" style={{ marginBottom: '10px' }}>
                      {a.selfMaker}
                    </div>
                  ) : approveBlock ? (
                    <div className="alert-warn" role="status" style={{ marginBottom: '10px' }}>
                      {blockText(approveBlock)}
                    </div>
                  ) : null}

                  {userCanDecide ? (
                    <div className="form-row" style={{ marginBottom: 0 }}>
                      <div className="form-group">
                        <label htmlFor="approval-decision-reason">{a.decisionLabel}</label>
                        <input
                          ref={noteRef}
                          id="approval-decision-reason"
                          type="text"
                          value={decisionReason}
                          onChange={(e) => setDecisionReason(e.target.value)}
                          placeholder={a.decisionPlaceholder}
                          disabled={!!blocks.both || submitting}
                        />
                      </div>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={!!approveBlock || submitting || !hasReason}
                        title={approveBlock ? blockText(approveBlock) : undefined}
                        onClick={() => void handleDecision('approve')}
                      >
                        {isSelfMaker ? a.cannotApproveOwn : a.approve}
                      </button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={!!blocks.both || submitting || !hasReason}
                        title={isSelfMaker ? a.cannotRejectOwn : blocks.both ? blockText(blocks.both) : undefined}
                        onClick={() => void handleDecision('reject')}
                      >
                        {a.reject}
                      </button>
                      <button type="button" className="btn" disabled={submitting} onClick={() => openSnooze(changeKey(activeChange.id))}>
                        {a.snooze}
                      </button>
                    </div>
                  ) : (
                    <div>
                      {a.noAuthority}
                    </div>
                  )}
                </div>
              ) : null}
              <details className="operations-evidence">
                <summary>{a.payload}</summary>
                <pre className="code-block">{JSON.stringify(activeChange.payload, null, 2)}</pre>
              </details>
            </div>
          ) : null}

          {listMode && userCanDecide && selectableIds.length > 0 ? (
            <div className="notice-box" role="group" aria-label={a.bulkGroup}>
              <div className="form-row" style={{ marginBottom: 0 }}>
                <button type="button" className="btn btn-sm" disabled={submitting} onClick={selectAll}>{a.selectAll}</button>
                {selected.size ? <button type="button" className="btn btn-sm" disabled={submitting} onClick={() => setSelected(new Set())}>{a.clearSelection}</button> : null}
                <span className="operations-meta" aria-live="polite">{a.selectedCount(selected.size, BULK_MAX)}</span>
              </div>
              {selected.size ? (
                <div className="form-row" style={{ marginBottom: 0, marginTop: '8px' }}>
                  <div className="form-group">
                    <label htmlFor="approval-bulk-note">{a.bulkNoteLabel}</label>
                    <input ref={bulkNoteRef} id="approval-bulk-note" type="text" value={bulkNote} disabled={submitting}
                      placeholder={a.decisionPlaceholder} onChange={(e) => setBulkNote(e.target.value)} />
                  </div>
                  <button type="button" className="btn btn-primary" disabled={!bulkReady} onClick={() => setBulkConfirm('approve')}>{a.approveSelected(selected.size)}</button>
                  <button type="button" className="btn btn-danger" disabled={!bulkReady} onClick={() => setBulkConfirm('reject')}>{a.rejectSelected(selected.size)}</button>
                </div>
              ) : null}
            </div>
          ) : null}

          <ApprovalQueue
            items={queue}
            user={props.user}
            activeId={activeChange?.id}
            cursor={cursorKey}
            listMode={listMode && userCanDecide}
            selected={selected}
            failures={failures}
            snoozedUntil={snoozedUntil}
            busy={submitting}
            rowRef={(key, el) => { if (el) rows.current.set(key, el); else rows.current.delete(key); }}
            onOpen={(c) => { setCursor(changeKey(c.id)); selectChange(c.id); }}
            onCursor={setCursor}
            onToggle={(id) => toggle([id])}
            onSnooze={openSnooze}
            onUnsnooze={(key) => void runSnooze(key, null)}
          />
        </div>
      ) : null}

      <ConfirmDialog
        open={bulkConfirm !== null}
        title={bulkConfirm === 'approve' ? a.confirmApproveTitle(selected.size) : a.confirmRejectTitle(selected.size)}
        body={a.bulkConfirmBody}
        confirmLabel={bulkConfirm === 'approve' ? a.approveSelected(selected.size) : a.rejectSelected(selected.size)}
        onConfirm={() => void runBulk(bulkConfirm === 'approve')}
        onCancel={() => setBulkConfirm(null)}
      />
    </section>
  );
}
