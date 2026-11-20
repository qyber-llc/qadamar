// GATE_PROFILE=production: the server refuses to start unless every secure setting below holds (docs/DEPLOY.md §5).
import { resolve } from 'node:path';
import { DEFAULT_RATE_LIMIT, DEFAULT_PEP_RATE_LIMIT } from './ratelimit.ts';
import pg from 'pg';
import { Auth, type Credentials } from './auth.ts';
import { isLoopback } from './oidc.ts';
import { databaseTlsFailures, databaseTlsFromEnv, postgresClientConfig } from './postgres-tls.ts';
import type { ServerOptions } from './server.ts';

export type Profile = 'demo' | 'production';
/** The schema SCHEMA (postgres.ts) creates the tables in; the checks name it rather than trusting search_path. */
export const GATE_SCHEMA = 'public';
export const GATE_TABLES = ['gate_doc', 'gate_audit', 'gate_audit_meta', 'gate_anchor', 'gate_audit_segment', 'gate_subject_identity', 'gate_sync', 'gate_token', 'gate_performed', 'gate_session', 'gate_blp_mark', 'gate_blp_session', 'gate_retired', 'gate_subject', 'gate_resource', 'gate_tuple', 'gate_state_change', 'gate_rate_limit'] as const;
/** Append-only tables: the service role may read and insert, never rewrite or empty them. */
const APPEND_ONLY = ['gate_audit', 'gate_anchor', 'gate_audit_segment', 'gate_performed', 'gate_retired', 'gate_state_change'] as const;
export const METRICS_TOKEN_MIN_LENGTH = 32;
const plainRemoteHttp = (raw: string | undefined): boolean => {
  if (raw === undefined) return false;
  try { const url = new URL(raw); return url.protocol !== 'https:' && !isLoopback(url); } catch { return true; }
};

export function profileOf(value: string | undefined): Profile {
  if (value === undefined || value === 'demo' || value === 'production') return value ?? 'demo';
  throw new Error('GATE_PROFILE must be demo or production');
}

/** Every failing requirement that can be checked without the database, in the order of docs/DEPLOY.md §5. */
export function productionFailures(o: ServerOptions, metricsToken = process.env.METRICS_TOKEN): string[] {
  const failures: string[] = [];
  if (!o.publicOrigin?.startsWith('https://')) failures.push('PUBLIC_ORIGIN must be https');
  // IdP sign-in always requires MFA: OIDC amr mfa/mca or OIDC_ACR, SAML an AuthnContextClassRef from SAML_AUTHN_CONTEXT
  // (required); neither can be configured without it
  if (!o.oidc && !o.saml) failures.push('OIDC_ISSUER or SAML_IDP_ENTITY_ID must be configured: console sign-in through the IdP with MFA');
  // with a database the accounts live in its credentials document: databaseRoleFailures checks them there
  if (passwordLoginOf(o) && !o.databaseUrl) failures.push(...totpFailures(Auth.accountsWithoutTotp(dataDirOf(o))));
  if (!o.databaseUrl) failures.push('DATABASE_URL must be set');
  else {
    try { failures.push(...databaseTlsFailures(o.databaseUrl, o.databaseTls ?? databaseTlsFromEnv({}, 'production'), 'production')); }
    catch (err) { failures.push(err instanceof Error ? err.message : String(err)); }
  }
  if (!o.signingKeySeal) failures.push('SIGNING_KEY_SEAL must be set');
  if (o.allowClearSigningKeys) failures.push('ALLOW_CLEAR_SIGNING_KEYS must be off: the shared signing keyring is sealed with SIGNING_KEY_SEAL');
  if (o.policySignatureAdopt) failures.push('POLICY_SIGNATURE_ADOPT must be off: adopt an unsigned bundle once in the demo profile, then start in production');
  if ((o.sodHistory ?? 'server') !== 'server') failures.push('SOD_HISTORY must be server: separation of duty trusts only server-recorded history');
  if (o.blpSessionRequired !== true) failures.push('BLP_SESSION_REQUIRED must be true: classified reads and cleared writes carry a PDP-issued context.sessionToken, so the session high-water mark is kept');
  if (!metricsToken || metricsToken.length < METRICS_TOKEN_MIN_LENGTH) failures.push(`METRICS_TOKEN must be set, at least ${METRICS_TOKEN_MIN_LENGTH} characters`);
  if (!o.tsa?.url.startsWith('https://') || !o.tsa.caFile) failures.push('TSA_URL (https) and TSA_CA_FILE must be set');
  if (o.clock !== undefined) failures.push('CLOCK must not be set: a fixed clock is for demos');
  if (!o.breakGlass) failures.push('BREAK_GLASS_WEBHOOK and BREAK_GLASS_WEBHOOK_SECRET must be set');
  // the notifier itself refuses every plain http URL (notify.ts), loopback included
  else if (!o.breakGlass.url.startsWith('https://')) failures.push('BREAK_GLASS_WEBHOOK must use https');
  if (plainRemoteHttp(o.tracing?.endpoint)) failures.push('OTEL_EXPORTER_OTLP_ENDPOINT must use https (plain http only on loopback)');
  return failures;
}

/** A stateless replica (GATE_REPLICA_OF) has no database, console or anchoring of its own: the checks that apply to it. */
export function replicaProductionFailures(o: ServerOptions, metricsToken = process.env.METRICS_TOKEN): string[] {
  const failures: string[] = [];
  if (!o.replicaOf?.startsWith('https://')) failures.push('GATE_REPLICA_OF must use https');
  if (!o.tls && !o.publicOrigin?.startsWith('https://')) failures.push('TLS_CERT_FILE and TLS_KEY_FILE, or an https PUBLIC_ORIGIN (TLS at a proxy), must be set: PEPs reach the replica over TLS');
  if (!metricsToken || metricsToken.length < METRICS_TOKEN_MIN_LENGTH) failures.push(`METRICS_TOKEN must be set, at least ${METRICS_TOKEN_MIN_LENGTH} characters`);
  if (o.clock !== undefined) failures.push('CLOCK must not be set: a fixed clock is for demos');
  if (plainRemoteHttp(o.tracing?.endpoint)) failures.push('OTEL_EXPORTER_OTLP_ENDPOINT must use https (plain http only on loopback)');
  return failures;
}

/** The role in DATABASE_URL must not be a superuser, own or belong to the owner of a gate table, or have to create
 *  them (it would then own them): an owner role migrates first (docs/API.md 3.9.1). Runs before any migration. */
const dataDirOf = (o: ServerOptions): string => resolve(o.dataDir ?? 'data/runtime');
/** Password sign-in: on unless an IdP is configured, as server.ts decides. */
const passwordLoginOf = (o: ServerOptions): boolean => o.passwordLogin ?? !(o.oidc || o.saml);
const totpFailures = (missing: string[]): string[] => missing.length
  ? [`PASSWORD_LOGIN is on but these local accounts have no active TOTP: ${missing.join(', ')} (turn it off, or enrol TOTP in the demo profile first)`] : [];

/** `passwordLoginDir`: password sign-in is on, so every local account in the credentials document (or, before the
 *  first start imported it, in that DATA_DIR's credentials.json) must have active TOTP. */
export async function databaseRoleFailures(url: string, passwordLoginDir?: string, databaseTls = databaseTlsFromEnv()): Promise<string[]> {
  const client = new pg.Client(postgresClientConfig(url, databaseTls));
  try {
    await client.connect();
    // direct or indirect membership counts: a member can SET ROLE to the privileged role
    const role = await client.query<{ superuser: boolean; bypass: boolean }>(`
      SELECT bool_or(r.rolsuper) AS superuser, bool_or(r.rolbypassrls OR r.rolcreaterole) AS bypass
      FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER')`);
    const tables = await client.query<{ name: string; present: boolean; owned: boolean | null; rewritable: boolean | null }>(
      `SELECT t.name, c.oid IS NOT NULL AS present, pg_has_role(current_user, c.relowner, 'MEMBER') AS owned,
         CASE WHEN c.oid IS NULL OR NOT (t.name = ANY($2::text[])) THEN false
           ELSE has_table_privilege(current_user, c.oid, 'UPDATE') OR has_table_privilege(current_user, c.oid, 'DELETE')
             OR has_table_privilege(current_user, c.oid, 'TRUNCATE') END AS rewritable
       FROM unnest($1::text[]) WITH ORDINALITY AS t(name, n)
       LEFT JOIN pg_namespace ns ON ns.nspname = $3
       LEFT JOIN pg_class c ON c.relname = t.name AND c.relnamespace = ns.oid AND c.relkind IN ('r', 'p')
       ORDER BY t.n`, [[...GATE_TABLES], [...APPEND_ONLY], GATE_SCHEMA]);
    const failures: string[] = [];
    if (role.rows[0]?.superuser !== false) failures.push('DATABASE_URL role is (or is a member of) a superuser');
    if (role.rows[0]?.bypass !== false) failures.push('DATABASE_URL role has (or is a member of a role with) BYPASSRLS or CREATEROLE');
    const missing = tables.rows.filter((t) => !t.present).map((t) => t.name);
    const owned = tables.rows.filter((t) => t.owned).map((t) => t.name);
    const rewritable = tables.rows.filter((t) => t.rewritable).map((t) => t.name);
    if (missing.length) failures.push(`DATABASE_URL: tables missing from schema ${GATE_SCHEMA} (an owner role must create them first): ${missing.join(', ')}`);
    if (owned.length) failures.push(`DATABASE_URL role owns (or is a member of the owner of) ${owned.join(', ')}`);
    if (rewritable.length) failures.push(`DATABASE_URL role may UPDATE, DELETE or TRUNCATE ${rewritable.join(', ')}`);
    if (passwordLoginDir !== undefined && !missing.includes('gate_doc')) {
      const row = await client.query<{ body: string }>(`SELECT body FROM ${GATE_SCHEMA}.gate_doc WHERE name = 'credentials'`);
      const body = row.rows[0]?.body;
      failures.push(...totpFailures(body === undefined ? Auth.accountsWithoutTotp(passwordLoginDir) : Auth.withoutTotp(JSON.parse(body) as Credentials)));
    }
    return failures;
  } catch (err) {
    return [`DATABASE_URL: the role could not be checked (${err instanceof Error ? err.message : 'unknown error'})`];
  } finally { await client.end().catch(() => undefined); }
}

/** The checks that need the database (listen(), before anything is migrated). */
export const databaseFailures = (o: ServerOptions & { databaseUrl: string }): Promise<string[]> =>
  databaseRoleFailures(o.databaseUrl, passwordLoginOf(o) ? dataDirOf(o) : undefined, o.databaseTls ?? databaseTlsFromEnv({}, 'production'));

export function refuse(failures: readonly string[]): void {
  if (failures.length) throw new Error(`GATE_PROFILE=production refused to start:\n- ${failures.join('\n- ')}`);
}

/** The secure-configuration baseline of a node, for evidence packs: which controls are on, never a secret value or
 *  a URL that could carry one (origins only). `productionDeviations` lists what GATE_PROFILE=production would refuse;
 *  the database role checks (databaseRoleFailures) run at start in production and are not repeated here. */
export const DEMO_WORLD_WARNING = 'ALLOW_DEMO_WORLD is on in the production profile: a first start may seed the demo world (fictional people and grants); use it for local test deployments only';
export function configurationBaseline(o: ServerOptions, metricsToken = process.env.METRICS_TOKEN): Record<string, unknown> {
  const origin = (raw: string | undefined): string | null => {
    if (raw === undefined) return null;
    try { return new URL(raw).origin; } catch { return null; }
  };
  return {
    profile: o.profile ?? 'demo',
    transport: { nativeTls: Boolean(o.tls), minTlsVersion: o.tls ? 'TLSv1.2' : null, publicOrigin: origin(o.publicOrigin),
      trustedProxies: (o.trustedProxies ?? '').split(',').map((e) => e.trim()).filter(Boolean) },
    consoleSignIn: { oidcIssuer: origin(o.oidc?.issuer), oidcAcr: o.oidc?.acr ?? null, samlIdpSso: origin(o.saml?.idpSsoUrl),
      samlAuthnContext: o.saml?.authnContext ?? null, passwordLogin: passwordLoginOf(o) },
    storage: { postgres: Boolean(o.databaseUrl), postgresTls: o.databaseUrl ? (() => { const tls = o.databaseTls ?? databaseTlsFromEnv({}, o.profile === 'production' ? 'production' : 'demo');
      return { mode: tls.mode, privateCa: Boolean(tls.caFile), clientCertificate: Boolean(tls.certFile) }; })() : null,
      signingKeysSealed: Boolean(o.signingKeySeal), clearSigningKeysAllowed: Boolean(o.allowClearSigningKeys),
      // SIGNING_KEY_SEAL_PREVIOUS set: a seal key rotation is in progress (remove it once the start audited seal_key_rotated)
      sealRotationInProgress: Boolean(o.signingKeySealPrevious),
      // GATE_CLUSTER / GATE_NODE_ID / GATE_MAX_STALENESS_MS: which chain this node writes and how stale it may decide
      cluster: Boolean(o.databaseUrl && o.cluster), nodeId: o.databaseUrl ? o.nodeId ?? '0' : null,
      maxStalenessMs: o.databaseUrl && o.cluster ? o.maxStalenessMs ?? 2000 : null },
    audit: { tsa: origin(o.tsa?.url), tsaCaPinned: Boolean(o.tsa?.caFile), anchorIntervalSeconds: o.tsa ? o.tsa.intervalSeconds ?? 3600 : null,
      retentionDays: o.retentionDays ?? null, subjectPseudonyms: true, siemPush: Boolean(o.siem), siemReceiver: origin(o.siem?.url) },
    separationOfDuty: o.sodHistory ?? 'server',
    blpSessionRequired: o.blpSessionRequired === true, blpSessionsPerSubject: o.blpSessionsPerSubject ?? 4,
    blpSessionCreationPerMinute: o.blpSessionCreationRateLimit ?? 60,
    breakGlassNotices: origin(o.breakGlass?.url),
    tracing: origin(o.tracing?.endpoint),
    scimBearerFromEnv: Boolean(o.scim?.bearerToken),
    metricsTokenSet: Boolean(metricsToken && metricsToken.length >= METRICS_TOKEN_MIN_LENGTH),
    rateLimitPerMinute: o.rateLimit ?? DEFAULT_RATE_LIMIT, pepRateLimitPerMinute: o.pepRateLimit ?? DEFAULT_PEP_RATE_LIMIT,
    clockPinned: o.clock !== undefined,
    policySignatureAdopt: Boolean(o.policySignatureAdopt),
    // ALLOW_DEMO_WORLD: a production node may have seeded its first start from the toy world's fictional people
    demoWorldAllowed: Boolean(o.allowDemoWorld),
    warnings: o.profile === 'production' && o.allowDemoWorld ? [DEMO_WORLD_WARNING] : [],
    productionDeviations: productionFailures(o, metricsToken),
  };
}
