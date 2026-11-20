import { createServer as httpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { resolve } from 'node:path';
import { Store, fileBacking, type Backing } from './store.ts';
import { Audit, type AuditLog } from './audit.ts';
import { appendAnchorFile, loadAnchorFile, requestAnchor } from './anchor.ts';
import { Auth, type Credentials } from './auth.ts';
import { CHECKPOINT_KEY_LABEL, decodeSeal, derivedKey, Tokens, type SigningKeyDisk } from './tokens.ts';
import { resealAtRest, sealedUnderPrevious } from './seal-rotation.ts';
import { HOP_KEY_LABEL, leaderOrigin } from './forward.ts';
import { createHandler } from './router.ts';
import { Oidc, isLoopback, type OidcConfig } from './oidc.ts';
import { Saml, type SamlConfig } from './saml.ts';
import type { Runtime, SodHistory } from './runtime.ts';
import { checkPolicySignature } from './policy-signature.ts';
import type { AuditPoint, PgLedger, PgLedgerOptions } from './postgres.ts';
import { databaseTlsFromEnv, type DatabaseTls } from './postgres-tls.ts';
import type { PerformedLog } from './store.ts';
import type { TokenTable } from './tokens.ts';
import { Scim, type ScimOptions } from './scim.ts';
import { SiemExporter, type SiemConfig, type SiemHooks } from './siem.ts';
import { BreakGlassNotifier, type WebhookConfig, type WebhookHooks } from './notify.ts';
import { configurationBaseline, databaseFailures, DEMO_WORLD_WARNING, productionFailures, refuse, type Profile } from './profile.ts';
import { PSEUDONYM_KEY_LABEL } from './admin/privacy.ts';
import { metrics } from './metrics.ts';
import { expireEmergencies } from './admin/break-glass.ts';
import type { ApprovalPrefs } from './admin/inbox.ts';
import { Tracer, type TracingConfig } from './tracing.ts';
import { trustedProxies } from './proxy.ts';
import { Sessions } from './sessions.ts';
import { PepSessions, type SessionRevocation } from './pep-sessions.ts';
import { FileSubjectIdentities, SUBJECT_TOUCH_MS } from './audit-subjects.ts';
import { mkdirSync, readFileSync } from 'node:fs';
import { HttpError } from './http.ts';
import { Replica, replicaOrigin } from './replica.ts';
import { ReplicaSource } from './replica-source.ts';
import { derive, REPLICA_CHECKPOINT_LABEL, replicaId, replicaKeyFor } from './replica-protocol.ts';
import { replicaProductionFailures } from './profile.ts';

export interface ServerOptions {
  /** Partition ingress supplies the tenant on replica feed requests too. */
  tenantId?: string;
  /** production refuses to start unless every secure setting holds (profile.ts, docs/DEPLOY.md §5); demo by default. */
  profile?: Profile;
  host?: string; port?: number; dataDir?: string; worldDir?: string; staticDir?: string;
  clock?: string | (() => string); rateLimit?: number; pepRateLimit?: number;
  /** Comma-separated addresses or CIDR ranges of the reverse proxies in front of the node (TRUSTED_PROXIES, proxy.ts):
   *  only a request from one of them has its client address read from X-Forwarded-For. Empty: the header is ignored. */
  trustedProxies?: string;
  /** External https origin when a proxy terminates TLS: cookies become Secure, HSTS is sent, OIDC redirects to it. */
  publicOrigin?: string;
  /** Serve TLS directly (PEM). */
  tls?: { cert: string | Buffer; key: string | Buffer };
  /** Console sign-in through the organisation's IdP; password sign-in is then off unless passwordLogin is true. */
  oidc?: OidcConfig;
  /** SAML 2.0 Web SSO, beside or instead of OIDC; the same rule for password sign-in. */
  saml?: SamlConfig;
  passwordLogin?: boolean;
  /** PEP old-secret overlap and bootstrap plaintext lifetime, in seconds. */
  pepRotationGraceSeconds?: number;
  initialCredentialsTtlSeconds?: number;
  /** Base64url or hex 32-byte key used to seal decision-token private keys at rest. */
  signingKeySeal?: string;
  /** SIGNING_KEY_SEAL_PREVIOUS, during a rotation: what it sealed is re-sealed under signingKeySeal at start (audited),
   *  after which it is no longer needed (seal-rotation.ts, docs/handbook/operations/rotate-credentials.md). */
  signingKeySealPrevious?: string;
  /** AUDIT_CHECKPOINT_MIGRATE: the head hash of an older non-empty unkeyed file chain, reviewed by the operator; its first keyed
   *  start authenticates exactly that head (audited). Bound to the hash, the value is spent as soon as the chain grows. */
  auditCheckpointMigration?: string;
  /** With databaseUrl and no signingKeySeal, start anyway and keep the private signing keys in clear in PostgreSQL. */
  allowClearSigningKeys?: boolean;
  /** DEMO_ALLOW_REMOTE: the demo profile binds a non-loopback address only with this set (it then warns at start). */
  allowRemoteDemo?: boolean;
  /** ALLOW_DEMO_WORLD: production may seed its first start from a world marked `"demo": true` (local test overlays only). */
  allowDemoWorld?: boolean;
  /** PostgreSQL control plane (state, tokens, audit, anchors). Several nodes may point at it: without `cluster` one
   *  serves and the others wait in listen() to take over; with it every node decides and one leads the admin plane.
   *  Without it, files in dataDir (single node, demo). */
  databaseUrl?: string;
  /** DATABASE_TLS: verify-full (production default), require, or disable (non-production or local only). */
  databaseTls?: DatabaseTls;
  /** GATE_NODE_ID: this node's audit chain ("0" by default: the chain of earlier versions). */
  nodeId?: string;
  /** GATE_CLUSTER: every node serves the PDP API; the admin plane stays on the leader (docs/API.md §3.9.1). */
  cluster?: boolean;
  /** GATE_MAX_STALENESS_MS: a cluster node refuses decisions when it last confirmed the shared state longer ago (2000). */
  maxStalenessMs?: number;
  /** GATE_ADVERTISE_URL: this node's internal address, published while it leads: followers forward admin and SCIM
   *  requests to it (with SIGNING_KEY_SEAL), or name it in their 409 answers. */
  advertiseUrl?: string;
  /** Deterministic database timing hooks for integration tests. */
  databaseHooks?: Pick<PgLedgerOptions, 'onScanStart' | 'onScanBatch' | 'afterCommit' | 'beforeSync' | 'onDecisionLock' | 'onPepSessionLock'>;
  /** Runs after a mark-relevant decision while its local session queue is held. */
  decisionHooks?: { afterDecision?: () => Promise<void> };
  recheckIntervalMs?: number;
  /** AUDIT_RETENTION_DAYS: file mode seals and removes the expired prefix at start and daily; PostgreSQL uses the owner ops script. */
  retentionDays?: number;
  /** RFC 3161 timestamp authority for the audit head (https), anchored every intervalSeconds (default 3600). */
  tsa?: { url: string; intervalSeconds?: number; caFile?: string };
  /** The store failed under this node: it now answers 503 and should be restarted (main.ts exits). */
  onFatal?: (err: Error) => void;
  /** SCIM 2.0 provisioning; without a bearer token, the credential is minted by POST /admin/v1/scim/credential. */
  scim?: ScimOptions;
  /** Push export of audit rows to an https webhook, every intervalSeconds (default 30). */
  siem?: SiemConfig & { intervalSeconds?: number };
  /** Transport hooks for integration tests (loopback http receiver). */
  siemHooks?: Omit<SiemHooks, 'commit'>;
  /** Console user id -> further resource owner ids that user answers for (RESOURCE_OWNERS); its own id always counts. */
  resourceOwners?: ReadonlyMap<string, readonly string[]>;
  /** "server": SoD-constrained actions ignore caller-supplied makerId and priorActions (SOD_HISTORY). Default "server". */
  sodHistory?: SodHistory;
  /** BLP_SESSION_REQUIRED: a cleared subject's writes and every read above L0 need a session. Production accepts only
   *  PDP-issued tokens; the demo profile keeps the deprecated raw-id compatibility mode. */
  blpSessionRequired?: boolean;
  /** BLP_SESSIONS_PER_PEP: the session marks one PEP credential may hold (sessions.ts DEFAULT_SESSIONS_PER_PEP). */
  blpSessionsPerPep?: number;
  /** BLP_SESSIONS_PER_SUBJECT: concurrent open tokens for one (PEP credential, subject). */
  blpSessionsPerSubject?: number;
  /** BLP_SESSIONS_PER_CREDENTIAL: concurrent open tokens for one PEP credential over all its subjects. */
  blpSessionsPerCredential?: number;
  /** BLP_SESSION_CREATION_PER_MINUTE: a separate token bucket per PEP credential. */
  blpSessionCreationRateLimit?: number;
  /** Sign the stored policy bundle at startup when it is unsigned or signed by a key not in the keyring (POLICY_SIGNATURE_ADOPT). */
  policySignatureAdopt?: boolean;
  /** Signed notice to an https webhook when an emergency access opens, is revoked or expires. */
  breakGlass?: WebhookConfig;
  breakGlassHooks?: WebhookHooks;
  /** OpenTelemetry trace export over OTLP/HTTP JSON (OTEL_EXPORTER_OTLP_ENDPOINT). */
  tracing?: TracingConfig;
  /** GATE_REPLICA_KEYS, on a database node: the replicas (id -> key) it serves the signed feed and audit ingestion. */
  replicaKeys?: ReadonlyMap<string, Buffer>;
  /** GATE_REPLICA_OF: this node is a stateless replica of the database nodes at that origin (no DATABASE_URL). */
  replicaOf?: string;
  /** GATE_REPLICA_KEY: the replica's secret (32 bytes, base64url or hex), as listed in the database nodes' GATE_REPLICA_KEYS. */
  replicaKey?: string;
  /** GATE_REPLICA_PIN: the database nodes' signing keys (JWK x) the replica trusts at its first start. */
  replicaPins?: readonly string[];
  /** GATE_REPLICA_CA_FILE: the CA (PEM) that verifies the database nodes' TLS certificate. */
  replicaCaFile?: string;
  /** GATE_REPLICA_AUDIT_LAG_MS: a replica refuses decisions while a durable audit row waits longer to reach the database. */
  replicaAuditLagMs?: number;
}
export interface PdpServer {
  listen: (port?: number, host?: string, origin?: string) => Promise<void>; close: () => Promise<void>; readonly url: string;
  /** Partition ingress uses the original socket, preserving client address and transport checks. */
  handle: (req: IncomingMessage, res: ServerResponse) => void;
  /** Timestamps the current audit head now (the timer does it every interval). */
  anchor: () => Promise<void>;
  /** Pushes the audit rows not yet acknowledged to the SIEM webhook now (the timer does it every interval). */
  exportAudit: () => Promise<void>;
  /** Audits and notifies the emergencies that expired since the last check (the timer does it every minute), then
   *  waits until every notice so far is delivered or given up. */
  notifyExpired: () => Promise<void>;
  /** Exports the queued trace spans now (the exporter does it every 5 s); never rejects. */
  flushTraces: () => Promise<void>;
}
export function createServer(options: ServerOptions = {}): PdpServer {
  const production = (options.profile ?? 'demo') === 'production';
  const replicaMode = options.replicaOf !== undefined;
  const databaseTls = options.databaseTls ?? databaseTlsFromEnv(process.env, production ? 'production' : 'demo');
  const preflight = production ? replicaMode ? replicaProductionFailures(options) : productionFailures({ ...options, databaseTls }) : [];
  // with a database, its role check joins the list in listen(), before anything is migrated
  if (production && !options.databaseUrl) refuse(preflight);
  const host = options.host ?? '127.0.0.1'; const port = options.port ?? 8787;
  const clock = options.clock;
  const now: () => string = typeof clock === 'function' ? clock : typeof clock === 'string' && clock.startsWith('fixed:')
    ? () => new Date(clock.slice(6)).toISOString() : () => new Date().toISOString();
  if (clock !== undefined && typeof clock !== 'function' && !clock.startsWith('fixed:')) throw new Error('CLOCK must be fixed:<ISO>');
  const started = Date.parse(now());
  if (!Number.isFinite(started)) throw new Error('Invalid clock');
  if (options.retentionDays !== undefined && (!Number.isSafeInteger(options.retentionDays) || options.retentionDays < 1 || options.retentionDays > 36_500)) throw new Error('AUDIT_RETENTION_DAYS must be an integer in 1..36500');
  if (options.retentionDays !== undefined && !options.signingKeySeal) throw new Error('AUDIT_RETENTION_DAYS requires SIGNING_KEY_SEAL for authenticated segment seals');
  const replicaKey = replicaMode ? decodeSeal(options.replicaKey, 'GATE_REPLICA_KEY') : undefined;
  if (replicaMode) {
    if (options.databaseUrl) throw new Error('GATE_REPLICA_OF and DATABASE_URL exclude each other: a replica has no database');
    if (!replicaKey) throw new Error('GATE_REPLICA_OF needs GATE_REPLICA_KEY');
    replicaOrigin(options.replicaOf!); replicaId(options.nodeId);
  }
  if (options.replicaKeys?.size && !options.databaseUrl) throw new Error('GATE_REPLICA_KEYS needs DATABASE_URL: only a database node serves replicas');
  // a replica writing this node's own chain would wait on its chain lock: refused outright
  if (options.replicaKeys && replicaKeyFor(options.replicaKeys, options.nodeId ?? '0')) throw new Error('GATE_REPLICA_KEYS must not name this node\'s own GATE_NODE_ID');
  // production lists this with every other failure in listen(), after the database role check
  if (!production && options.databaseUrl && options.signingKeySeal === undefined && !options.allowClearSigningKeys) {
    throw new Error('SIGNING_KEY_SEAL is required with DATABASE_URL (the signing keyring is stored in PostgreSQL); set ALLOW_CLEAR_SIGNING_KEYS=true to store it in clear');
  }
  const sealKey = decodeSeal(options.signingKeySeal);
  const previousSealKey = decodeSeal(options.signingKeySealPrevious, 'SIGNING_KEY_SEAL_PREVIOUS');
  if (previousSealKey && (!sealKey || sealKey.equals(previousSealKey))) throw new Error('SIGNING_KEY_SEAL_PREVIOUS needs a different SIGNING_KEY_SEAL: the new key');
  const dataDir = resolve(options.dataDir ?? 'data/runtime');
  const anchorFile = resolve(dataDir, 'anchors.jsonl');
  let base = '';
  /** Bound to a non-loopback address: /metrics then needs METRICS_TOKEN in every profile. */
  let remoteBind = false;
  const publicOrigin = options.publicOrigin ? new URL(options.publicOrigin).origin : undefined;
  if (publicOrigin && !publicOrigin.startsWith('https://') && !isLoopback(new URL(publicOrigin))) throw new Error('PUBLIC_ORIGIN must use https');
  if (options.oidc && !publicOrigin) throw new Error('OIDC needs PUBLIC_ORIGIN for its redirect URI');
  if (options.saml && !publicOrigin) throw new Error('SAML needs PUBLIC_ORIGIN for its assertion consumer service');
  if (options.tsa && !options.tsa.url.startsWith('https://') && !isLoopback(new URL(options.tsa.url))) throw new Error('TSA_URL must use https');
  if (options.advertiseUrl !== undefined) leaderOrigin(options.advertiseUrl); // followers send console sessions there
  const security = { publicOrigin, oidc: options.oidc ? new Oidc(options.oidc, publicOrigin!) : undefined,
    saml: options.saml ? new Saml(options.saml, publicOrigin!) : undefined,
    passwordLogin: options.passwordLogin ?? !(options.oidc || options.saml) };
  let ledger: PgLedger | undefined;
  let replica: Replica | undefined;
  let rt: Runtime | undefined;
  let handler: ReturnType<typeof createHandler> | undefined;
  let siem: SiemExporter | undefined;
  const notifier = options.breakGlass ? new BreakGlassNotifier(options.breakGlass, async (notice, result) => {
    if (!rt) return;
    metrics(rt).observeNotice(result.outcome);
    if (result.outcome === 'sent') return;
    rt.audit.append({ type: 'break_glass', actor: 'system', action: 'notify_failed', effect: 'deny', subject: notice.subjectId, resource: notice.resourceId,
      details: { id: notice.emergencyId, event: notice.event, attempts: result.attempts, error: result.error } });
    await rt.commit?.();
  }, options.breakGlassHooks) : undefined;
  const tracer = options.tracing ? new Tracer(options.tracing) : undefined;
  const proxies = trustedProxies(options.trustedProxies);
  /** Local console accounts: protected at each subject purge, as the world subjects. */
  let consoleIds = (): string[] => [];
  const build = (): void => {
    const db = ledger;
    const performedLog: PerformedLog | undefined = db ? { load: () => db.takePerformed(), append: (row) => db.stagePerformed(row),
      settle: (ref, check) => db.settleReservation(ref, check) } : undefined;
    if (production && options.allowDemoWorld) console.warn(`WARNING: ${DEMO_WORLD_WARNING}`);
    const store = new Store(dataDir, resolve(options.worldDir ?? 'examples/toy-domain'), now(), db?.backing('state'), performedLog,
      { refuseDemoWorld: production && !options.allowDemoWorld, ...(db ? { retired: db.retiredLog } : {}) });
    // PostgreSQL: one shared document per item. The first start of this version (no credentials document yet) imports
    // the node's DATA_DIR files once; after that the files are neither read nor written.
    const migrating = db !== undefined && db.backing('credentials').load() === undefined;
    const imported: string[] = [];
    const doc = <T>(name: string, file: string): Backing<T> => {
      const local = fileBacking<T>(resolve(store.dir, file));
      if (!db) return local;
      const shared = db.backing<T>(name);
      if (migrating && shared.load() === undefined) {
        const found = local.load();
        if (found !== undefined) { shared.save(found); imported.push(file); }
      }
      return shared;
    };
    const keyring = doc<SigningKeyDisk>('signing_keys', 'signing-keys.json');
    const credentials = doc<Credentials>('credentials', 'credentials.json');
    consoleIds = () => credentials.load()?.users.map((user) => user.id) ?? [];
    let audit: AuditLog;
    if (ledger) audit = ledger.auditLog(now);
    else {
      const file = new Audit(resolve(store.dir, 'audit.jsonl'), now, {
        checkpointKey: derivedKey(options.signingKeySeal, CHECKPOINT_KEY_LABEL), previousCheckpointKey: derivedKey(options.signingKeySealPrevious, CHECKPOINT_KEY_LABEL),
        checkpointRotationInProgress: Boolean(sealKey && previousSealKey && sealedUnderPrevious(keyring.load(), credentials.load(), sealKey, previousSealKey)),
        ...(options.auditCheckpointMigration ? { checkpointMigration: options.auditCheckpointMigration } : {}),
        subjects: new FileSubjectIdentities(resolve(store.dir, 'audit-subjects.json'), now),
      });
      file.anchors = loadAnchorFile(anchorFile); audit = file;
    }
    // every start checks that the sealed material opens, before the audit: a wrong key also fails the checkpoint's HMAC,
    // and the operator must read "wrong key", not "tampering". A rotation re-seals here, committed with its audit row.
    const resealed = sealKey ? resealAtRest(keyring, credentials, sealKey, previousSealKey) : undefined;
    if (!audit.verify().verified) throw new Error('Audit integrity failure');
    if (resealed) {
      const writer = !db || db.leader;
      if (writer && (resealed.signingKeys || resealed.totpSecrets || db?.checkpointRekeyed)) {
        audit.append({ type: 'security', actor: 'system', action: 'seal_key_rotated', details: { ...resealed, checkpointRekeyed: Boolean(db?.checkpointRekeyed) } });
        console.info(`Re-sealed under SIGNING_KEY_SEAL: ${resealed.signingKeys} signing key(s), ${resealed.totpSecrets} TOTP secret(s)${db?.checkpointRekeyed ? ', the audit checkpoint' : ''}`);
      } else if (previousSealKey && !resealed.signingKeys && !resealed.totpSecrets && !db?.checkpointRekeyed) {
        // every start, every node: the old key must not stay configured once the rotation is done
        console.warn('SIGNING_KEY_SEAL_PREVIOUS is set but nothing at rest is sealed under it any more (the rotation is complete): remove it from every node and restart');
      }
    }
    // before any bootstrap file is written: a refused bundle must leave nothing behind. In PostgreSQL mode the
    // keyring is the shared document, so a standby that takes over verifies against the keys the old primary used.
    const tokens = new Tokens(store.dir, now, db?.backing('tokens'), { signingKeySeal: options.signingKeySeal, signingKeySealPrevious: options.signingKeySealPrevious,
      ...(db ? { keyring, table: {
        insert: (jti, entry) => db.stageToken(jti, entry),
        consume: (jti, resource, sid, accept, refresh, blpSession) => db.consumeToken(jti, resource, (stored, session) => accept(stored as Parameters<typeof accept>[0], session), sid, refresh, blpSession),
      } satisfies TokenTable } : {}) });
    checkPolicySignature(store, tokens, audit, options.policySignatureAdopt);
    const auth = new Auth(store.dir, audit, now, undefined, { pepRotationGraceSeconds: options.pepRotationGraceSeconds,
      initialCredentialsTtlSeconds: options.initialCredentialsTtlSeconds, onBootstrapStatus: (message) => console.info(message),
      credentials, lockouts: doc('lockouts', 'lockouts.json'), signingKeySeal: options.signingKeySeal, signingKeySealPrevious: options.signingKeySealPrevious,
      production, ...(db ? { sessions: db.sessionTable() } : {}) });
    const sessions = new Sessions(options.blpSessionRequired === true, undefined, db ? undefined : fileBacking(resolve(store.dir, 'sessions.json')),
      db ? { stage: (row) => db.stageMark(row), load: (keys) => db.loadMarks(keys), decision: (keys, task) => db.decision(keys, task) } : undefined, options.blpSessionsPerPep);
    sessions.requireTokens = production;
    const pepSessions = new PepSessions(tokens, sessions, audit, now, Date.now, db ? undefined : fileBacking(resolve(store.dir, 'blp-sessions.json')),
      db ? db.pepSessionTable() : undefined, options.blpSessionsPerSubject, options.blpSessionsPerCredential,
      doc<SessionRevocation[]>('blp_revocations', 'blp-revocations.json'));
    rt = { store, audit, tokens, now, started, decisions: 0, sessions, pepSessions,
      ...(options.resourceOwners ? { resourceOwners: options.resourceOwners } : {}), sodHistory: options.sodHistory ?? 'server',
      ...(db ? { commit: () => db.commit() } : {}), ...(options.tsa ? { anchoring: { url: options.tsa.url } } : {}),
      ...(notifier ? { notifyBreakGlass: (notice) => notifier.send(notice) } : {}),
      baseline: configurationBaseline({ ...options, databaseTls }), ...(options.signingKeySeal ? { pseudonymKey: derivedKey(options.signingKeySeal, PSEUDONYM_KEY_LABEL) } : {}),
      ...(db ? { node: { id: db.node, leader: () => db.leader, fresh: () => db.fresh(), leaderUrl: () => db.leaderUrl } } : {}),
      ...(options.decisionHooks?.afterDecision ? { afterDecision: options.decisionHooks.afterDecision } : {}),
      approvalPrefs: doc<ApprovalPrefs>('approval_prefs', 'approval-prefs.json') };
    const scim = new Scim(rt, doc('scim', 'scim-credential.json'), options.scim);
    const cursor = doc<{ seq: number }>('siem', 'siem-cursor.json');
    siem = options.siem ? new SiemExporter(audit, cursor, options.siem,
      { ...options.siemHooks, ...(db ? { commit: () => db.commit() } : {}) }) : undefined;
    const hopKey = db && options.cluster ? derivedKey(options.signingKeySeal, HOP_KEY_LABEL) : undefined;
    const runtime = rt;
    const replicaSource = db && options.replicaKeys?.size
      ? new ReplicaSource(db, tokens, audit, () => runtime.commit!(), { blpSessionRequired: options.blpSessionRequired === true }, options.replicaKeys) : undefined;
    handler = createHandler(rt, auth, { ...options, security, scim, tracer, proxies, metricsTokenRequired: () => remoteBind, ...(hopKey ? { hopKey } : {}),
      ...(replicaSource ? { replicaSource } : {}),
      ...(db?.cluster ? { rateLimitLease: (key, capacity, perMinute, amount) => db.leaseRateLimit(key, capacity, perMinute, amount) } : {}) }, () => publicOrigin ?? base);
    if (db) {
      const exporter = siem;
      // a follower follows what the leader commits; a follower taking the lead starts from the same documents
      db.onReload = (records) => {
        store.reload(records); auth.reload(); tokens.reload(); pepSessions.reload(); exporter?.reload();
        checkPolicySignature(store, tokens, audit); // as at start: no decision on a bundle the keyring did not sign
      };
      db.onPerformed = (rows) => store.addPerformed(rows);
      store.addPerformed(db.takePerformed());
    }
    if (imported.length) console.info(`Imported into PostgreSQL from DATA_DIR (committed at start; the files are no longer used): ${imported.join(', ')}`);
  };
  /** Replica mode: the documents come from the signed feed; the audit is this replica's own durable keyed chain. */
  const buildReplica = (r: Replica): void => {
    const memory = <T>(): Backing<T> => { let value: T | undefined; return { load: () => value, save: (next) => { value = next; } }; };
    const store = new Store(dataDir, resolve(options.worldDir ?? 'examples/toy-domain'), now(), r.backing('state'));
    const audit = new Audit(resolve(store.dir, 'audit.jsonl'), now, { checkpointKey: derive(r.key, REPLICA_CHECKPOINT_LABEL), node: r.id, durable: true,
      subjects: r.identities, onDurable: (rows) => r.durable(rows) });
    if (!audit.verify().verified) throw new Error('Audit integrity failure');
    // public keys only: a replica signs nothing (requests that need a decision token or an assertion are forwarded)
    const tokens = new Tokens(store.dir, now, memory(), { keyring: r.backing<SigningKeyDisk>('signing_keys') });
    checkPolicySignature(store, tokens, audit);
    const auth = new Auth(store.dir, audit, now, undefined, { pepRotationGraceSeconds: options.pepRotationGraceSeconds, onBootstrapStatus: (m) => console.info(m),
      credentials: r.backing<Credentials>('credentials'), lockouts: memory(), production });
    const sessions = new Sessions(r.config.blpSessionRequired);
    sessions.requireTokens = production;
    const pepSessions = new PepSessions(tokens, sessions, audit, now, Date.now, undefined, undefined, undefined, undefined, r.backing<SessionRevocation[]>('blp_revocations'));
    rt = { store, audit, tokens, now, started, decisions: 0, baseline: configurationBaseline(options), sessions, pepSessions,
      // a write that did not reach the disk latches the audit: memory may be ahead of it, so this replica stops (main.ts)
      commit: () => audit.flush().catch((err: unknown) => {
        handler = undefined; options.onFatal?.(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Audit storage unavailable');
      }),
      node: { id: r.id, role: 'replica', leader: () => false, fresh: () => r.fresh(), leaderUrl: () => r.leader.origin, metrics: () => r.metrics() } };
    handler = createHandler(rt, auth, { ...options, scim: undefined, security, tracer, proxies, metricsTokenRequired: () => remoteBind, replica: r }, () => publicOrigin ?? base);
    r.state = () => store.state;
    r.onReload = (records) => {
      store.reload(records); auth.reload(); tokens.reload(); pepSessions.reload();
      checkPolicySignature(store, tokens, audit); // as a follower: no decision on a bundle the keyring did not sign
      sessions.required = r.config.blpSessionRequired;
    };
  };
  if (!options.databaseUrl && !replicaMode) build();
  let anchoring: Promise<void> | undefined;
  const anchor = (): Promise<void> => {
    // one at a time: the timer and a manual call must not anchor the same head twice
    anchoring ??= anchorOnce().finally(() => { anchoring = undefined; });
    return anchoring;
  };
  const anchorOnce = async (): Promise<void> => {
    if (!rt?.anchoring || (ledger && !ledger.leader)) return;
    const state = rt.anchoring;
    try {
      await rt.commit?.();
      if (!rt.audit.verify().verified) throw new Error('Audit chain does not verify; not anchoring it');
      let head: AuditPoint = ledger ? ledger.committed : (rt.audit as Audit).tip();
      if (!ledger && (head.seq === 0 || head.seq === (rt.audit.anchors.at(-1)?.seq ?? 0))) return;
      if (ledger) {
        const verified = await ledger.recheck();
        if (!verified) throw new Error('Audit rows in the database differ from the chain this node wrote');
        head = verified; // anchor exactly the snapshot heads that were verified, even when joining an older scan
      }
      if (head.seq === 0 || head.seq === (rt.audit.anchors.at(-1)?.seq ?? 0)) return;
      // several chains: the authority timestamps the hash of every chain's head
      const anchored = { ...await requestAnchor(state.url, head, options.tsa?.caFile), ...(head.heads ? { heads: head.heads } : {}) };
      if (ledger) await ledger.saveAnchor(anchored); else appendAnchorFile(anchorFile, anchored);
      rt.audit.anchors.push(anchored);
      delete state.lastError;
    } catch (err) {
      state.lastError = err instanceof Error ? err.message : 'Anchoring failed';
      console.error(`Audit anchoring failed: ${state.lastError}`);
    }
  };
  let retaining: Promise<void> | undefined;
  const retainFile = (): Promise<void> => retaining ??= (async () => {
    const audit = rt?.audit;
    if (!options.retentionDays || ledger || !(audit instanceof Audit)) return;
    const cutoff = new Date(Date.parse(now()) - options.retentionDays * 86_400_000).toISOString();
    const plan = audit.planRetention(cutoff);
    if (!plan) return;
    const anchored = options.tsa ? await requestAnchor(options.tsa.url, plan.head, options.tsa.caFile) : undefined;
    if (anchored) appendAnchorFile(anchorFile, anchored); // durable before the prefix it authenticates can be removed
    audit.applyRetention(plan, anchored);
  })().finally(() => { retaining = undefined; });
  const notifyExpired = async (): Promise<void> => {
    if (!rt || !notifier || (ledger && !ledger.leader)) return;
    try {
      const notices = expireEmergencies(rt);
      if (notices.length) await rt.commit?.(); // audited and marked before anything leaves
      for (const notice of notices) notifier.send(notice);
    } catch (err) { console.error(`Break-glass expiry check failed: ${err instanceof Error ? err.message : 'unknown error'}`); }
    await notifier.settled();
  };
  let sweeping: NodeJS.Timeout | undefined;
  let timer: NodeJS.Timeout | undefined;
  let recheck: NodeJS.Timeout | undefined;
  let exporting: NodeJS.Timeout | undefined;
  let retention: NodeJS.Timeout | undefined;
  let purging: NodeJS.Timeout | undefined;
  // daily, every profile, retention or not: idle mappings of non-world ids go (on PostgreSQL the leader does it)
  const purgeSubjects = async (): Promise<void> => {
    if (!rt || replicaMode) return;
    try { await rt.audit.purgeSubjects?.([...rt.store.state.subjects.map((subject) => subject.id), ...consoleIds()]); } catch (err) {
      console.error(`Subject mapping purge failed: ${err instanceof Error ? err.message : 'unknown error'}`);
    }
  };
  // a failed push keeps its cursor: the same rows are retried at the next interval (at-least-once)
  const exportAudit = (): Promise<void> => (ledger && !ledger.leader ? undefined : siem?.flush().catch((err: unknown) => {
    console.error(`SIEM export failed: ${err instanceof Error ? err.message : 'unknown error'}`);
  })) ?? Promise.resolve();
  const serve = (req: IncomingMessage, res: ServerResponse): void => {
    if (handler) { void handler(req, res); return; }
    res.statusCode = 503; res.setHeader('Content-Type', 'application/json'); res.end('{"error":"unavailable"}');
  };
  const server = options.tls ? httpsServer({ cert: options.tls.cert, key: options.tls.key, minVersion: 'TLSv1.2' }, serve) : httpServer(serve);
  server.requestTimeout = 30_000; server.headersTimeout = 10_000;
  return {
    handle: serve,
    get url(): string { return base; },
    anchor,
    exportAudit,
    notifyExpired,
    flushTraces: () => tracer?.flush() ?? Promise.resolve(),
    listen: async (listenPort = port, listenHost = host, origin?: string): Promise<void> => {
      remoteBind = !isLoopbackHost(listenHost);
      if (!production && remoteBind) {
        if (!options.allowRemoteDemo) throw new Error(`GATE_PROFILE=demo listens on loopback only (HOST=${listenHost}): the demo has seeded accounts, a toy world and optional controls off. Use GATE_PROFILE=production, or set DEMO_ALLOW_REMOTE=true to expose the demo anyway`);
        console.warn(`WARNING: DEMO_ALLOW_REMOTE=true: the demo profile is listening on ${listenHost}, reachable from other hosts. It is not a production configuration (seeded accounts, toy world, production checks off); /metrics answers only with METRICS_TOKEN`);
      }
      if (!options.databaseUrl && options.retentionDays && !replicaMode) await retainFile();
      if (replicaMode && !replica) {
        mkdirSync(dataDir, { recursive: true, mode: 0o700 });
        const opened = await Replica.open({ leader: options.replicaOf!, id: options.nodeId!, key: replicaKey!, dataDir, tenantId: options.tenantId,
          ...(options.replicaPins ? { pins: options.replicaPins } : {}), ...(options.replicaCaFile ? { ca: readFileSync(options.replicaCaFile) } : {}),
          ...(options.maxStalenessMs ? { maxStalenessMs: options.maxStalenessMs } : {}), ...(options.replicaAuditLagMs ? { maxAuditLagMs: options.replicaAuditLagMs } : {}) });
        try { buildReplica(opened); await opened.start(rt!.audit as Audit); } catch (err) { await opened.close(); throw err; }
        replica = opened;
      }
      if (options.databaseUrl && !ledger) {
        if (production) refuse([...preflight, ...await databaseFailures({ ...options, databaseUrl: options.databaseUrl, databaseTls })]);
        // a standby waits here until the active node lets go of the database
        ledger = await (await import('./postgres.ts')).PgLedger.open(options.databaseUrl, (err) => {
          handler = undefined; // memory may be ahead of the database: stop answering
          options.onFatal?.(err);
        }, { ...options.databaseHooks, databaseTls,
          now, checkpointKey: derivedKey(options.signingKeySeal, CHECKPOINT_KEY_LABEL), pseudonymiseSubjects: true,
          previousCheckpointKey: derivedKey(options.signingKeySealPrevious, CHECKPOINT_KEY_LABEL),
          rotating: (doc) => Boolean(sealKey && previousSealKey && sealedUnderPrevious(doc('signing_keys'), doc('credentials'), sealKey, previousSealKey)),
          node: options.nodeId, cluster: options.cluster, maxStalenessMs: options.maxStalenessMs, advertiseUrl: options.advertiseUrl });
        try {
          build();
          await ledger.ensureSubjects(rt!.store.state.subjects.map((subject) => subject.id));
          await rt!.commit!(); // first boot seeds the state (a follower writes no document)
        } catch (err) { await ledger.close(); ledger = undefined; throw err; } // let a standby take over
        const started = ledger;
        if (started.startup.from > 0) {
          // started from a checkpoint: the rows before it are verified again now, in the background, while serving
          console.info(`Audit verified from checkpoint seq ${started.startup.from} (${started.startup.rowsRead} rows read); verification of every chain from its genesis runs in the background (/readyz audit.fullChain=false until it ends)`);
          void started.periodicRecheck().catch(() => undefined);
        }
      }
      if (ledger && !recheck) {
        // a row rewritten in the database after start shows in verify within five minutes, anchoring or not
        recheck = setInterval(() => void ledger?.periodicRecheck().catch(() => undefined), options.recheckIntervalMs ?? 300_000); recheck.unref();
      }
      if (!replicaMode && !purging) { void purgeSubjects(); purging = setInterval(() => void purgeSubjects(), SUBJECT_TOUCH_MS); purging.unref(); }
      if (options.retentionDays && !ledger && !retention) {
        retention = setInterval(() => void retainFile().catch((err: unknown) => console.error(`Audit retention failed: ${err instanceof Error ? err.message : 'unknown error'}`)), 86_400_000); retention.unref();
      }
      if (options.siem && !exporting) { exporting = setInterval(() => void exportAudit(), (options.siem.intervalSeconds ?? 30) * 1000); exporting.unref(); }
      if (notifier && !sweeping) { sweeping = setInterval(() => void notifyExpired(), 60_000); sweeping.unref(); }
      if (options.tsa && !timer) { timer = setInterval(() => void anchor(), (options.tsa.intervalSeconds ?? 3600) * 1000); timer.unref(); }
      if (origin !== undefined) { base = origin; return; }
      await new Promise<void>((accept, reject) => {
      const onError = (err: Error): void => reject(err);
      server.once('error', onError);
      server.listen(listenPort, listenHost, () => {
        server.off('error', onError);
        const address = server.address();
        if (!address || typeof address === 'string') { reject(new Error('No server address')); return; }
        base = `${options.tls ? 'https' : 'http'}://${listenHost.includes(':') ? `[${listenHost}]` : listenHost}:${address.port}`;
        accept();
      });
      });
    },
    close: async (): Promise<void> => {
      clearInterval(timer); clearInterval(recheck); clearInterval(exporting); clearInterval(sweeping); clearInterval(retention); clearInterval(purging);
      await retaining?.catch(() => undefined);
      await new Promise<void>((accept, reject) => {
        if (!server.listening) { accept(); return; }
        server.close((err) => err ? reject(err) : accept()); server.closeIdleConnections();
      });
      rt?.sessions?.flush();
      await replica?.close();
      await ledger?.close();
      await tracer?.close();
    },
  };
}

/** Loopback listen addresses: localhost, 127.0.0.0/8 and ::1 (with or without brackets). */
export function isLoopbackHost(host: string): boolean {
  return host === 'localhost' || /^127(\.\d{1,3}){3}$/.test(host) || host === '::1' || host === '[::1]';
}
