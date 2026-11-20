import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ConsoleRole, PepCredential, ScimCredentialInfo, SigningKey } from '../api/types';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { SecretPanel } from '../components/SecretPanel';
import { ErrorAlert, LoadingState } from '../components/UiStates';
import { useT } from '../i18n';
import '../styles/operations.css';
import { canManagePepCredentials, canRotateScimCredential } from '../utils/permissions';
import { forbidden, PepCredentialsCard, ScimCard, SigningKeysCard, type Loaded } from './CredentialsCards';
import { ApprovalModesCard } from './ApprovalModesCard';

type Confirm = { readonly kind: 'revoke'; readonly credential: PepCredential } | { readonly kind: 'keys' } | { readonly kind: 'scim' };

const settle = <T,>(r: PromiseSettledResult<T>): Loaded<T> => (r.status === 'fulfilled' ? { value: r.value } : { error: r.reason });

/** docs/API.md §3.10 and §3.11: PEP credentials, decision-token signing keys and the SCIM credential. The server
 *  checks every role again; hidden actions only spare a 403, which still reads as "not for your role". */
export function CredentialsScreen(props: { readonly roles: readonly ConsoleRole[] }) {
  const s = useT().security;
  const canManage = canManagePepCredentials(props.roles);
  const [pep, setPep] = useState<Loaded<readonly PepCredential[]> | null>(null);
  const [keys, setKeys] = useState<Loaded<readonly SigningKey[]> | null>(null);
  const [scim, setScim] = useState<Loaded<ScimCredentialInfo> | null>(null);
  const [secret, setSecret] = useState<{ readonly name: string; readonly value: string } | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState('');
  const [resourceTypes, setResourceTypes] = useState<readonly string[]>([]);

  const loadAll = useCallback(async () => {
    const [p, k, c, schema] = await Promise.allSettled([
      api.getPepCredentials().then((r) => r.items), api.getSigningKeys().then((r) => r.items), api.getScimCredential(), api.getSchema(),
    ]);
    // without the schema the form offers no resource type: the credential is then created for decisions only
    setResourceTypes(schema.status === 'fulfilled' ? Object.keys(schema.value.resourceTypes) : []);
    setPep(settle(p));
    setKeys(settle(k));
    setScim(settle(c));
  }, []);

  useEffect(() => { void loadAll(); }, [loadAll]);

  /** Runs one action: busy state, the error and the announcement are handled alike; true when it succeeded. */
  const run = async (action: () => Promise<string>): Promise<boolean> => {
    setBusy(true);
    setActionError(null);
    setNotice('');
    try {
      setNotice(await action());
      await loadAll();
      return true;
    } catch (err) {
      setActionError(err);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const createPep = (name: string, types: readonly string[]) => run(async () => {
    const res = await api.createPepCredential(name, types);
    setSecret({ name: res.credential.name, value: res.secret });
    return s.pep.createdNotice(res.credential.name);
  });
  const rotatePep = (c: PepCredential) => void run(async () => {
    const res = await api.rotatePepCredential(c.id);
    setSecret({ name: res.credential.name, value: res.secret });
    return s.pep.rotatedNotice(c.name);
  });

  const onConfirm = () => {
    const c = confirm;
    setConfirm(null);
    if (c?.kind === 'revoke') void run(async () => { await api.revokePepCredential(c.credential.id); return s.pep.revokedNotice(c.credential.name); });
    if (c?.kind === 'keys') void run(async () => { await api.rotateSigningKey(); return s.keys.rotatedNotice; });
    if (c?.kind === 'scim') {
      void run(async () => {
        const res = await api.rotateScimCredential();
        setSecret({ name: s.scim.secretName, value: res.credential });
        return s.scim.rotatedNotice;
      });
    }
  };
  const retry = () => void loadAll();

  return (
    <section className="operations-screen" aria-labelledby="title-credentials">
      <div className="screen-header">
        <div>
          <h1 className="screen-title" id="title-credentials">{s.title}</h1>
          <p className="screen-subtitle">{s.subtitle}</p>
        </div>
      </div>

      <div className="sr-only" role="status">{notice}</div>
      {actionError ? <ErrorAlert error={actionError} contextTitle={forbidden(actionError) ? s.notForRole : s.actionFailed} /> : null}
      {secret ? <SecretPanel name={secret.name} secret={secret.value} onDone={() => setSecret(null)} /> : null}

      {!pep || !keys || !scim ? <LoadingState label={s.loading} /> : (
        <>
          <PepCredentialsCard
            loaded={pep}
            canManage={canManage}
            busy={busy}
            onRetry={retry}
            onCreate={createPep}
            resourceTypes={resourceTypes}
            onRotate={rotatePep}
            onRevoke={(credential) => setConfirm({ kind: 'revoke', credential })}
          />
          <SigningKeysCard loaded={keys} canManage={canManage} busy={busy} onRetry={retry} onRotate={() => setConfirm({ kind: 'keys' })} />
          <ScimCard loaded={scim} canRotate={canRotateScimCredential(props.roles)} busy={busy} onRetry={retry} onRotate={() => setConfirm({ kind: 'scim' })} />
          <ApprovalModesCard />
        </>
      )}

      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.kind === 'revoke' ? s.pep.confirmTitle(confirm.credential.name) : confirm?.kind === 'keys' ? s.keys.confirmTitle : s.scim.confirmTitle}
        body={confirm?.kind === 'revoke' ? s.pep.confirmBody : confirm?.kind === 'keys' ? s.keys.confirmBody : s.scim.confirmBody}
        confirmLabel={confirm?.kind === 'revoke' ? s.pep.revoke : confirm?.kind === 'keys' ? s.keys.rotate : s.scim.rotate}
        onConfirm={onConfirm}
        onCancel={() => setConfirm(null)}
      />
    </section>
  );
}
