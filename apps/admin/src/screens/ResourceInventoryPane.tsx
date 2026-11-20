import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type {
  ChangeRecord, ConsoleRole, InventoryPage, InventoryResource, RegisterResourcesPayload, RetiredResource, SchemaResponse,
} from '../api/types';
import { DateText, EmptyState, ErrorAlert, LevelBadge, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';
import { formatRef } from '../utils/expr';
import { canViewRetiredResources } from '../utils/permissions';
import { buildHref } from '../utils/router';

const PAGE = 50;

/** One paged listing. The server pages by cursor only, so the cursors of the pages before give "previous". */
function usePages<T>(fetchPage: (cursor: string) => Promise<InventoryPage<T>>, enabled = true) {
  const [cursors, setCursors] = useState<readonly string[]>(['']);
  const [page, setPage] = useState<InventoryPage<T> | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  const cursor = cursors.at(-1) ?? '';
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    setPage(null);
    setError(null);
    fetchPage(cursor).then((p) => { if (active) setPage(p); }, (err: unknown) => { if (active) setError(err); });
    return () => { active = false; };
  }, [fetchPage, cursor, enabled, attempt]);
  const next = page?.next;
  return {
    page, error, first: (cursors.length - 1) * PAGE, retry: () => setAttempt((n) => n + 1),
    prev: cursors.length > 1 ? () => setCursors(cursors.slice(0, -1)) : undefined,
    next: next ? () => setCursors([...cursors, next]) : undefined,
  };
}

/** aria-disabled rather than disabled: the focused button stays focusable on the first and last page. */
function Pager(props: { readonly label: string; readonly first: number; readonly page: InventoryPage<unknown>; readonly prev?: () => void; readonly next?: () => void }) {
  const m = useT().model.inventory;
  const count = props.page.items.length;
  return (
    <nav className="filter-bar" aria-label={m.pages(props.label)} style={{ marginTop: '12px', alignItems: 'center' }}>
      <span className="metric-sub" role="status">{count ? m.range(props.first + 1, props.first + count, props.page.total) : ''}</span>
      <button type="button" className="btn btn-sm" aria-disabled={!props.prev} onClick={() => props.prev?.()}>{m.previous}</button>
      <button type="button" className="btn btn-sm" aria-disabled={!props.next} onClick={() => props.next?.()}>{m.next}</button>
    </nav>
  );
}

const Badges = (props: { readonly items: readonly string[]; readonly none: string }) => (
  <div className="badge-group">
    {props.items.length > 0 ? props.items.map((c) => <span key={c} className="badge">{c}</span>) : <span className="metric-sub">{props.none}</span>}
  </div>
);

function RegisteredCard(props: { readonly type: string }) {
  const m = useT().model.inventory;
  const [fetchPage] = useState(() => (cursor: string) => api.getResourceInventory(props.type, cursor, PAGE));
  const { page, error, first, retry, prev, next } = usePages<InventoryResource>(fetchPage);
  const label = m.tableLabel(props.type);
  return (
    <div className="card" role="region" aria-labelledby="inventory-registered-title">
      <h2 className="card-title" id="inventory-registered-title">{label}</h2>
      {error ? <ErrorAlert error={error} contextTitle={m.loadFailed} onRetry={retry} /> : !page ? <LoadingState label={m.loading} /> : page.total === 0 ? (
        <EmptyState title={m.empty} detail={m.emptyDetail} />
      ) : (
        <>
          <div className="table-wrap" tabIndex={0} role="region" aria-label={label}>
            <table>
              <thead>
                <tr>
                  <th scope="col">{m.resource}</th>
                  <th scope="col">{m.level}</th>
                  <th scope="col">{m.compartments}</th>
                  <th scope="col">{m.integrityOwner}</th>
                  <th scope="col">{m.contentClasses}</th>
                  <th scope="col">{m.parent}</th>
                  <th scope="col">{m.version}</th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((r) => (
                  <tr key={r.id}>
                    <td><strong className="mono">{r.id}</strong>{r.title !== r.id ? <div className="metric-sub">{r.title}</div> : null}</td>
                    <td><LevelBadge level={r.level} /></td>
                    <td><Badges items={r.compartments} none={m.none} /></td>
                    <td className="mono">{r.integrity} · {r.owner ?? '—'}</td>
                    <td><Badges items={r.contentClasses} none={m.none} /></td>
                    <td className="mono">{r.parent ? formatRef(r.parent) : '—'}</td>
                    <td className="mono">{r.version}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager label={label} first={first} page={page} prev={prev} next={next} />
        </>
      )}
    </div>
  );
}

function RetiredCard(props: { readonly type: string; readonly allowed: boolean }) {
  const m = useT().model.inventory;
  const [fetchPage] = useState(() => (cursor: string) => api.getRetiredResources(props.type, cursor, PAGE));
  const { page, error, first, retry, prev, next } = usePages<RetiredResource>(fetchPage, props.allowed);
  const label = m.retiredTable(props.type);
  return (
    <div className="card" role="region" aria-labelledby="inventory-retired-title">
      <h2 className="card-title" id="inventory-retired-title">{m.retiredTitle}</h2>
      <p className="metric-sub">{m.retiredIntro}</p>
      {!props.allowed ? <div className="notice-box" role="status">{m.retiredOwner}</div>
        : error ? <ErrorAlert error={error} contextTitle={m.loadFailed} onRetry={retry} /> : !page ? <LoadingState label={m.loading} /> : page.total === 0 ? (
          <EmptyState title={m.retiredEmpty} />
        ) : (
          <>
            <div className="table-wrap" tabIndex={0} role="region" aria-label={label}>
              <table>
                <thead>
                  <tr>
                    <th scope="col">{m.resource}</th>
                    <th scope="col">{m.version}</th>
                    <th scope="col">{m.retiredAt}</th>
                    <th scope="col">{m.registeredAgain}</th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((r) => (
                    <tr key={r.id}>
                      <td className="mono"><strong>{r.id}</strong></td>
                      <td className="mono">{r.version}</td>
                      <td><DateText iso={r.retiredAt} /></td>
                      <td>{r.registeredAgain ? <span className="badge badge-warn">{m.yes}</span> : m.no}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager label={label} first={first} page={page} prev={prev} next={next} />
          </>
        )}
    </div>
  );
}

const names = (refs: readonly { readonly type: string; readonly id: string }[] | undefined, type: string): string[] =>
  (refs ?? []).filter((r) => r.type === type).map((r) => r.id);

/** Pending register_resources changes naming this type; approving or rejecting them stays on the approvals screen. */
export function PendingRegistrations(props: { readonly type: string; readonly changes: readonly ChangeRecord[] | null; readonly error: unknown; readonly onRetry: () => void }) {
  const m = useT().model.inventory;
  const label = m.pendingTable(props.type);
  const mine = (props.changes ?? []).filter((c) => c.kind === 'register_resources').map((c) => {
    const p = c.payload as RegisterResourcesPayload;
    return { c, register: names(p.resources, props.type), retire: names(p.retire, props.type) };
  }).filter((x) => x.register.length + x.retire.length > 0);
  return (
    <div className="card" role="region" aria-labelledby="inventory-pending-title">
      <h2 className="card-title" id="inventory-pending-title">
        <span>{m.pendingTitle}</span>
        {props.changes ? <span className="badge">{mine.length}</span> : null}
      </h2>
      <p className="metric-sub">{m.pendingIntro}</p>
      {props.error ? <ErrorAlert error={props.error} contextTitle={m.loadFailed} onRetry={props.onRetry} /> : !props.changes ? <LoadingState label={m.loading} /> : mine.length === 0 ? (
        <EmptyState title={m.pendingEmpty} />
      ) : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label={label}>
          <table>
            <thead>
              <tr>
                <th scope="col">{m.change}</th>
                <th scope="col">{m.credential}</th>
                <th scope="col">{m.register}</th>
                <th scope="col">{m.retire}</th>
                <th scope="col">{m.reason}</th>
                <th scope="col">{m.review}</th>
              </tr>
            </thead>
            <tbody>
              {mine.map(({ c, register, retire }) => (
                <tr key={c.id}>
                  <td><span className="mono">{c.id}</span><div className="metric-sub">{m.proposed} <DateText iso={c.createdAt} /></div></td>
                  <td className="mono">{c.pepCredential?.id ?? '—'}</td>
                  <td><Badges items={register} none={m.none} /></td>
                  <td><Badges items={retire} none={m.none} /></td>
                  <td>{c.reason}</td>
                  <td><a className="btn btn-sm" href={buildHref('approvals', { status: 'pending', id: c.id })} aria-label={m.reviewLabel(c.id)}>{m.review}</a></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** docs/API.md §2.2 and §3.3: the resource inventory PEPs register, one type at a time; read-only for every role. */
export function ResourceInventoryPane(props: {
  readonly schema: SchemaResponse | null;
  readonly roles: readonly ConsoleRole[];
  readonly params: Readonly<Record<string, string>>;
  readonly setParams: (updates: Readonly<Record<string, string | undefined>>) => void;
}) {
  const m = useT().model.inventory;
  const types = Object.keys(props.schema?.resourceTypes ?? {});
  const type = props.params.rtype && types.includes(props.params.rtype) ? props.params.rtype : types[0] ?? '';
  const [changes, setChanges] = useState<readonly ChangeRecord[] | null>(null);
  const [changesError, setChangesError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setChanges(null);
    setChangesError(null);
    api.getChanges('pending').then((r) => { if (active) setChanges(r.items); }, (err: unknown) => { if (active) setChangesError(err); });
    return () => { active = false; };
  }, [attempt]);
  return (
    <>
      <div className="card">
        <p className="metric-sub">{m.intro}</p>
        <div className="form-row">
          <div className="form-group">
            <label htmlFor="inventory-type-select">{m.type}</label>
            <select id="inventory-type-select" value={type} onChange={(e) => props.setParams({ rtype: e.target.value })}>
              {types.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
        </div>
      </div>
      {type ? (
        <div key={type}>
          <RegisteredCard type={type} />
          <PendingRegistrations type={type} changes={changes} error={changesError} onRetry={() => setAttempt((n) => n + 1)} />
          <RetiredCard type={type} allowed={canViewRetiredResources(props.roles)} />
        </div>
      ) : null}
    </>
  );
}
