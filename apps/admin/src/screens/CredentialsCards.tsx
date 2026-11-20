import { useState } from 'react';
import { ApiError } from '../api/client';
import type { PepCredential, ScimCredentialInfo, SigningKey } from '../api/types';
import { DateText, EmptyState, ErrorAlert } from '../components/UiStates';
import { useT } from '../i18n';
import { formatDateHuman } from '../utils/expr';

/** One section's load: its value, or the error (a 403 reads as "not for your role"). */
export interface Loaded<T> { readonly value?: T; readonly error?: unknown }

export const forbidden = (err: unknown): boolean => err instanceof ApiError && err.status === 403;

function SectionError(props: { readonly error: unknown; readonly title: string; readonly onRetry: () => void }) {
  const s = useT().security;
  return forbidden(props.error)
    ? <div className="notice-box" role="status">{s.notForRole}</div>
    : <ErrorAlert error={props.error} contextTitle={props.title} onRetry={props.onRetry} />;
}

const ReadOnly = (props: { readonly text: string }) => (
  <div className="notice-box" style={{ marginTop: '12px', marginBottom: 0 }}>{props.text}</div>
);

/** docs/API.md §3.10: list for access admins and security officers; create, rotate and revoke for security officers. */
export function PepCredentialsCard(props: {
  readonly loaded: Loaded<readonly PepCredential[]>;
  readonly canManage: boolean;
  readonly busy: boolean;
  readonly onRetry: () => void;
  readonly onCreate: (name: string, resourceTypes: readonly string[]) => Promise<boolean>;
  readonly onRotate: (credential: PepCredential) => void;
  readonly onRevoke: (credential: PepCredential) => void;
  /** The policy resource types, offered for `resourceTypes` (docs/API.md §2.2); none offered when the schema is unavailable. */
  readonly resourceTypes?: readonly string[];
}) {
  const s = useT().security.pep;
  const [name, setName] = useState('');
  const [types, setTypes] = useState<readonly string[]>([]);
  const items = props.loaded.value;
  const trimmed = name.trim();
  const nameValid = trimmed.length >= 1 && trimmed.length <= 80;
  const submit = async () => {
    if (nameValid && !props.busy && await props.onCreate(trimmed, types)) { setName(''); setTypes([]); }
  };
  const toggle = (type: string, on: boolean) => setTypes(on ? [...types, type] : types.filter((t) => t !== type));

  return (
    <div className="card" role="region" aria-labelledby="pep-title">
      <h2 className="card-title" id="pep-title">
        <span>{s.title}</span>
        {items ? <span className="badge">{s.count(items.filter((c) => !c.revoked).length)}</span> : null}
      </h2>
      <p className="metric-sub">{s.intro}</p>
      {props.loaded.error ? <SectionError error={props.loaded.error} title={s.title} onRetry={props.onRetry} /> : items?.length === 0 ? (
        <EmptyState title={s.empty} detail={s.emptyDetail} />
      ) : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label={s.tableLabel}>
          <table>
            <thead>
              <tr>
                <th scope="col">{s.name}</th>
                <th scope="col">{s.created}</th>
                <th scope="col">{s.lastUsed}</th>
                <th scope="col">{s.rotated}</th>
                <th scope="col">{s.status}</th>
                <th scope="col">{s.resourceTypes}</th>
                {props.canManage ? <th scope="col">{s.actions}</th> : null}
              </tr>
            </thead>
            <tbody>
              {items?.map((c) => (
                <tr key={c.id}>
                  <td title={c.id}><strong>{c.name}</strong></td>
                  <td><DateText iso={c.created} /></td>
                  <td>{c.lastUsed ? <DateText iso={c.lastUsed} /> : s.never}</td>
                  <td><DateText iso={c.rotated} /></td>
                  <td>
                    {c.revoked
                      ? <><span className="badge badge-deny">{s.revoked}</span> <DateText iso={c.revoked} /></>
                      : <span className="badge badge-allow">{s.active}</span>}
                    {!c.revoked && c.previousValidUntil ? (
                      <div className="metric-sub" title={c.previousValidUntil}>{s.previousUntil(formatDateHuman(c.previousValidUntil))}</div>
                    ) : null}
                  </td>
                  <td>
                    <div className="badge-group">
                      {c.resourceTypes?.length ? c.resourceTypes.map((t) => <span key={t} className="badge mono">{t}</span>) : <span className="metric-sub">{s.noResourceTypes}</span>}
                    </div>
                  </td>
                  {props.canManage ? (
                    <td>
                      {c.revoked ? null : (
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                          <button type="button" className="btn btn-sm" disabled={props.busy} aria-label={s.rotateLabel(c.name)} onClick={() => props.onRotate(c)}>{s.rotate}</button>
                          <button type="button" className="btn btn-sm btn-danger" disabled={props.busy} aria-label={s.revokeLabel(c.name)} onClick={() => props.onRevoke(c)}>{s.revoke}</button>
                        </div>
                      )}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {props.loaded.error ? null : props.canManage ? (
        <form className="filter-bar" style={{ marginTop: '12px', alignItems: 'flex-end' }} onSubmit={(e) => { e.preventDefault(); void submit(); }}>
          <div className="form-group">
            <label htmlFor="pep-name-input">{s.createLabel}</label>
            <input id="pep-name-input" type="text" maxLength={80} required autoComplete="off" value={name} placeholder={s.createPlaceholder} onChange={(e) => setName(e.target.value)} />
          </div>
          {props.resourceTypes?.length ? (
            <fieldset className="form-group" aria-describedby="pep-types-hint">
              <legend>{s.resourceTypesLegend}</legend>
              <div className="badge-group">
                {props.resourceTypes.map((t) => (
                  <label key={t}>
                    <input type="checkbox" name="pep-resource-types" value={t} checked={types.includes(t)} onChange={(e) => toggle(t, e.target.checked)} /> <span className="mono">{t}</span>
                  </label>
                ))}
              </div>
              <p className="metric-sub" id="pep-types-hint">{s.resourceTypesHint}</p>
            </fieldset>
          ) : null}
          <button type="submit" className="btn btn-primary" disabled={!nameValid || props.busy}>{props.busy ? s.creating : s.create}</button>
        </form>
      ) : <ReadOnly text={s.readOnly} />}
    </div>
  );
}

/** docs/API.md §3.10: the keyring; rotation for security officers. */
export function SigningKeysCard(props: {
  readonly loaded: Loaded<readonly SigningKey[]>;
  readonly canManage: boolean;
  readonly busy: boolean;
  readonly onRetry: () => void;
  readonly onRotate: () => void;
}) {
  const s = useT().security.keys;
  const items = props.loaded.value;
  return (
    <div className="card" role="region" aria-labelledby="keys-title">
      <h2 className="card-title" id="keys-title"><span>{s.title}</span></h2>
      <p className="metric-sub">{s.intro}</p>
      {props.loaded.error ? <SectionError error={props.loaded.error} title={s.title} onRetry={props.onRetry} /> : items?.length === 0 ? <EmptyState title={s.empty} /> : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label={s.tableLabel}>
          <table>
            <thead>
              <tr><th scope="col">{s.kid}</th><th scope="col">{s.created}</th><th scope="col">{s.state}</th></tr>
            </thead>
            <tbody>
              {items?.map((k) => (
                <tr key={k.kid}>
                  <td className="mono">{k.kid}</td>
                  <td><DateText iso={k.created} /></td>
                  <td>
                    {k.active
                      ? <span className="badge badge-allow">{s.signing}</span>
                      : <span className="badge badge-warn" title={k.verifyUntil}>{s.verifyUntil(formatDateHuman(k.verifyUntil))}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {props.loaded.error ? null : props.canManage ? (
        <button type="button" className="btn btn-danger" style={{ marginTop: '12px' }} disabled={props.busy} onClick={props.onRotate}>
          {props.busy ? s.rotating : s.rotate}
        </button>
      ) : <ReadOnly text={s.readOnly} />}
    </div>
  );
}

/** docs/API.md §3.11: holder and last rotation; rotation for access admins only (they cannot approve changes). */
export function ScimCard(props: {
  readonly loaded: Loaded<ScimCredentialInfo>;
  readonly canRotate: boolean;
  readonly busy: boolean;
  readonly onRetry: () => void;
  readonly onRotate: () => void;
}) {
  const s = useT().security.scim;
  const info = props.loaded.value;
  return (
    <div className="card" role="region" aria-labelledby="scim-title">
      <h2 className="card-title" id="scim-title"><span>{s.title}</span></h2>
      <p className="metric-sub">{s.intro}</p>
      {props.loaded.error ? <SectionError error={props.loaded.error} title={s.title} onRetry={props.onRetry} /> : info?.source === 'none' ? (
        <EmptyState title={s.none} />
      ) : info?.source === 'env' ? (
        <div className="notice-box">{s.env}</div>
      ) : (
        <div>
          <div className="kv-row"><span className="kv-label">{s.holder}</span><span className="mono">{info?.rotatedBy}</span></div>
          <div className="kv-row"><span className="kv-label">{s.lastRotated}</span><span>{info?.rotated ? <DateText iso={info.rotated} /> : s.notRecorded}</span></div>
        </div>
      )}
      <p className="notice-box" style={{ marginTop: '12px' }}>{s.twoPerson}</p>
      {props.loaded.error || info?.source === 'env' ? null : props.canRotate ? (
        <button type="button" className="btn btn-danger" disabled={props.busy} onClick={props.onRotate}>
          {props.busy ? s.rotating : s.rotate}
        </button>
      ) : <ReadOnly text={s.readOnly} />}
    </div>
  );
}
