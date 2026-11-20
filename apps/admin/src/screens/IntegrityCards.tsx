import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { CertificationsResponse, ChangeRecord, ConsoleRole, Ref, Reservation } from '../api/types';
import { DateText, EmptyState, ErrorAlert, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';
import { canViewCertifications, canViewReservations } from '../utils/permissions';

const ref = (r: Ref): string => `${r.type}:${r.id}`;

/** Certification records with their `current` state, and the procedures to recertify (docs/API.md §3.12). */
export function CertificationsCard(props: { readonly data: CertificationsResponse }) {
  const c = useT().integrity;
  const { items, missing, stale } = props.data;
  const uncertified = missing.filter((m) => !stale.some((s) => s.resourceType === m.resourceType && s.action === m.action));
  return (
    <div className="card" role="region" aria-labelledby="certifications-title">
      <h2 className="card-title">
        <span id="certifications-title">{c.certTitle}</span>
        <span className="badge">{c.certCount(items.length)}</span>
      </h2>
      <p className="screen-subtitle">{c.certIntro}</p>
      {stale.length ? (
        <div className="alert-warn" style={{ marginBottom: '12px' }}>
          <strong>{c.staleTitle(stale.length)}</strong>
          <ul>{stale.map((s) => <li key={`${s.resourceType}/${s.action}`} className="mono">{c.procedure(s.action, s.resourceType)}</li>)}</ul>
          <div>{c.staleDetail}</div>
        </div>
      ) : null}
      {uncertified.length ? (
        <div className="notice-box">
          <strong>{c.uncertifiedTitle(uncertified.length)}</strong>
          <ul>{uncertified.map((s) => <li key={`${s.resourceType}/${s.action}`} className="mono">{c.procedure(s.action, s.resourceType)}</li>)}</ul>
        </div>
      ) : null}
      {items.length === 0 ? <EmptyState title={c.certEmpty} /> : (
        <div className="table-wrap">
          <table aria-label={c.certTitle}>
            <thead>
              <tr>
                <th scope="col">{c.colProcedure}</th>
                <th scope="col">{c.colStatus}</th>
                <th scope="col">{c.colCertifiedBy}</th>
                <th scope="col">{c.colApprovedBy}</th>
                <th scope="col">{c.colCertifiedAt}</th>
                <th scope="col">{c.colPolicyVersion}</th>
                <th scope="col">{c.colChange}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={`${r.changeId}/${r.resourceType}/${r.action}`}>
                  <td className="mono">{c.procedure(r.action, r.resourceType)}</td>
                  <td><span className={r.current ? 'badge badge-allow' : 'badge badge-warn'}>{r.current ? c.current : c.stale}</span></td>
                  <td className="mono">{r.certifiedBy}</td>
                  <td className="mono">{r.approvedBy}</td>
                  <td><DateText iso={r.certifiedAt} /></td>
                  <td className="mono" title={r.policyVersion}>{r.policyVersion.slice(0, 12)}</td>
                  <td className="mono">{r.changeId}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Reservations no PEP settled, oldest first: they count for separation of duty until reconciled. */
export function ReservationsCard(props: { readonly items: readonly Reservation[] }) {
  const c = useT().integrity;
  return (
    <div className="card" role="region" aria-labelledby="reservations-title">
      <h2 className="card-title">
        <span id="reservations-title">{c.resTitle}</span>
        <span className={props.items.length ? 'badge badge-warn' : 'badge'}>{c.resCount(props.items.length)}</span>
      </h2>
      <p className="screen-subtitle">{c.resIntro}</p>
      {props.items.length === 0 ? <EmptyState title={c.resEmpty} /> : (
        <div className="table-wrap">
          <table aria-label={c.resTitle}>
            <thead>
              <tr>
                <th scope="col">{c.colReservation}</th>
                <th scope="col">{c.colSubject}</th>
                <th scope="col">{c.colResource}</th>
                <th scope="col">{c.colAction}</th>
                <th scope="col">{c.colReservedAt}</th>
                <th scope="col">{c.colPep}</th>
                <th scope="col">{c.colOnBehalfOf}</th>
              </tr>
            </thead>
            <tbody>
              {props.items.map((r) => (
                <tr key={r.reservation}>
                  <td className="mono">{r.reservation}</td>
                  <td className="mono">{ref(r.subject)}</td>
                  <td className="mono">{ref(r.resource)}</td>
                  <td className="mono">{r.action}</td>
                  <td><DateText iso={r.reservedAt} /></td>
                  <td className="mono">{r.pep ?? '—'}</td>
                  <td className="mono">{r.onBehalfOf?.map(ref).join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** A publish_policy proposal's certifications that approving it would make stale (docs/API.md §3.12). */
export function InvalidatedCertifications(props: { readonly items: ChangeRecord['invalidatesCertifications'] }) {
  const c = useT().integrity;
  if (!props.items?.length) return null;
  return (
    <div className="alert-warn" role="region" aria-labelledby="invalidated-certifications-title" style={{ marginBottom: '12px' }}>
      <strong id="invalidated-certifications-title">{c.invalidatesTitle(props.items.length)}</strong>
      <ul>
        {props.items.map((i) => (
          <li key={`${i.changeId}/${i.resourceType}/${i.action}`}>
            <span className="mono">{c.procedure(i.action, i.resourceType)}</span> ({c.certifiedBy(i.changeId)})
          </li>
        ))}
      </ul>
      <div>{c.invalidatesDetail}</div>
    </div>
  );
}

/** Loads what the signed-in roles may read; renders nothing for a role that may read neither. */
export function IntegrityPanel(props: { readonly roles: readonly ConsoleRole[] }) {
  const c = useT().integrity;
  const showCerts = canViewCertifications(props.roles);
  const showReservations = canViewReservations(props.roles);
  const [certs, setCerts] = useState<CertificationsResponse | null>(null);
  const [reservations, setReservations] = useState<readonly Reservation[] | null>(null);
  const [certError, setCertError] = useState<unknown>(null);
  const [resError, setResError] = useState<unknown>(null);

  const loadCerts = useCallback(async () => {
    setCertError(null);
    try { setCerts(await api.getCertifications()); } catch (err) { setCertError(err); }
  }, []);
  const loadReservations = useCallback(async () => {
    setResError(null);
    try { setReservations((await api.getReservations()).items); } catch (err) { setResError(err); }
  }, []);
  useEffect(() => { if (showCerts) void loadCerts(); }, [showCerts, loadCerts]);
  useEffect(() => { if (showReservations) void loadReservations(); }, [showReservations, loadReservations]);

  return (
    <>
      {showCerts ? (
        certError ? <ErrorAlert error={certError} contextTitle={c.certLoadError} onRetry={() => void loadCerts()} />
          : certs ? <CertificationsCard data={certs} /> : <LoadingState label={c.certLoading} />
      ) : null}
      {showReservations ? (
        resError ? <ErrorAlert error={resError} contextTitle={c.resLoadError} onRetry={() => void loadReservations()} />
          : reservations ? <ReservationsCard items={reservations} /> : <LoadingState label={c.resLoading} />
      ) : null}
    </>
  );
}
