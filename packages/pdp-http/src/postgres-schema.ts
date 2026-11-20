// The PostgreSQL schema and the service role's privileges (docs/API.md §3.9.1).
/** Idempotent; run by the owner role (the first start, when the service role owns nothing yet, or a DBA). Rows are JSON
 *  text, not jsonb: jsonb refuses \u0000 and lone surrogates, which callers can send. Grants decide who may write;
 *  the owner gives up UPDATE/DELETE/TRUNCATE on append-only evidence, and a separate service role should only get
 *  SELECT, INSERT on it. Filter metadata is derived and replaceable; the chained record remains the source of truth.
 *  Retention deletes are an owner-only maintenance operation: the DELETE RLS policy does not grant the service role the
 *  table privilege. gate_audit_segment authenticates each removed prefix; gate_subject_identity is the separate,
 *  erasable id/key mapping. Upgrades add the node columns, cluster tables, reservation columns, console/BLP tables, the
 *  retired-id log, (after 0.6.0) the audit seal/identity tables, per-record state and its change log, and the tuple
 *  grant-window columns. */
/** The newest object SCHEMA creates: a database without it is migrated at start (postgres.ts migrate), which runs the
 *  whole SCHEMA, so earlier additions are created with it. */
// gate_subject_identity_used is created last in SCHEMA: a database at 0.11.0 (no subject last-used column) lacks it and is
// migrated; the column is added as NULL for existing rows, so a mapping stored before the upgrade is never purged.
export const SCHEMA_MARKER = 'gate_subject_identity_used';
/** gate_retired, its row-level security and policies: also what scripts/ops/restore.sh creates, empty, when an archive
 *  predates the table (nothing was retired then). k8s.test.ts checks restore.sh carries exactly this. */
export const RETIRED_TABLE = `CREATE TABLE IF NOT EXISTS gate_retired (type text NOT NULL, id text NOT NULL, version bigint NOT NULL, retired_at text NOT NULL, node text NOT NULL, PRIMARY KEY (type, id, version));
ALTER TABLE gate_retired ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_retired FORCE ROW LEVEL SECURITY;`;
export const RETIRED_POLICY = 'CREATE POLICY gate_retired_read ON gate_retired FOR SELECT TO PUBLIC USING (true); CREATE POLICY gate_retired_append ON gate_retired FOR INSERT TO PUBLIC WITH CHECK (true);';
/** gate_session, its index, row-level security and policy: also what scripts/ops/restore.sh creates, empty, when an
 *  archive predates the table (sessions are disposable). k8s.test.ts checks restore.sh carries exactly this. */
export const SESSION_TABLE = `CREATE TABLE IF NOT EXISTS gate_session (id text PRIMARY KEY, body text NOT NULL, method text NOT NULL, oidc_sub text, oidc_sid text, created bigint NOT NULL, touched bigint NOT NULL);
CREATE INDEX IF NOT EXISTS gate_session_touched ON gate_session (touched);
ALTER TABLE gate_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_session FORCE ROW LEVEL SECURITY;`;
export const SESSION_POLICY = 'CREATE POLICY gate_session_rw ON gate_session FOR ALL TO PUBLIC USING (true) WITH CHECK (true);';
/** PDP-issued BLP sessions: the signed token is not stored, only its claims and last use. */
export const BLP_SESSION_TABLE = `CREATE TABLE IF NOT EXISTS gate_blp_session (sid text PRIMARY KEY, pep text NOT NULL, subject text NOT NULL, body text NOT NULL, seen bigint NOT NULL, exp bigint NOT NULL);
CREATE INDEX IF NOT EXISTS gate_blp_session_subject ON gate_blp_session (pep, subject);
CREATE INDEX IF NOT EXISTS gate_blp_session_seen ON gate_blp_session (seen);
CREATE INDEX IF NOT EXISTS gate_blp_session_exp ON gate_blp_session (exp);
ALTER TABLE gate_blp_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_blp_session FORCE ROW LEVEL SECURITY;`;
export const BLP_SESSION_POLICY = 'CREATE POLICY gate_blp_session_rw ON gate_blp_session FOR ALL TO PUBLIC USING (true) WITH CHECK (true);';
/** Disposable shared token buckets, also created empty when an archive predates cluster-wide rate limiting. */
export const RATE_LIMIT_TABLE = `CREATE TABLE IF NOT EXISTS gate_rate_limit (key text PRIMARY KEY, tokens double precision NOT NULL, at double precision NOT NULL, leased double precision NOT NULL);
ALTER TABLE gate_rate_limit ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_rate_limit FORCE ROW LEVEL SECURITY;`;
export const RATE_LIMIT_POLICY = 'CREATE POLICY gate_rate_limit_rw ON gate_rate_limit FOR ALL TO PUBLIC USING (true) WITH CHECK (true);';
/** One row per subject, resource or tuple. Position preserves the state document's array order (its digest covers order);
 *  state_version is diagnostic, while the dense record seq drives follower catch-up. A tuple's grant window (CBAC grant
 *  duration: notBefore ?? validFrom, notAfter ?? validTo) is derived into not_before/not_after for expiry queries;
 *  existing rows are backfilled from their body. Role assignments stay in the subject body. */
export const RECORD_TABLES = `CREATE TABLE IF NOT EXISTS gate_subject (type text NOT NULL, id text NOT NULL, position bigint NOT NULL, state_version bigint NOT NULL, body text NOT NULL, PRIMARY KEY (type, id));
CREATE INDEX IF NOT EXISTS gate_subject_position ON gate_subject (position);
CREATE TABLE IF NOT EXISTS gate_resource (type text NOT NULL, id text NOT NULL, position bigint NOT NULL, state_version bigint NOT NULL, body text NOT NULL, PRIMARY KEY (type, id));
CREATE INDEX IF NOT EXISTS gate_resource_position ON gate_resource (position);
CREATE TABLE IF NOT EXISTS gate_tuple (id text PRIMARY KEY, position bigint NOT NULL, state_version bigint NOT NULL, object_type text NOT NULL, object_id text NOT NULL, subject_type text NOT NULL, subject_id text NOT NULL, body text NOT NULL);
CREATE INDEX IF NOT EXISTS gate_tuple_position ON gate_tuple (position);
CREATE INDEX IF NOT EXISTS gate_tuple_object ON gate_tuple (object_type, object_id);
CREATE INDEX IF NOT EXISTS gate_tuple_subject ON gate_tuple (subject_type, subject_id);
ALTER TABLE gate_tuple ADD COLUMN IF NOT EXISTS not_before text;
ALTER TABLE gate_tuple ADD COLUMN IF NOT EXISTS not_after text;
UPDATE gate_tuple SET not_before = COALESCE(body::json ->> 'notBefore', body::json ->> 'validFrom'), not_after = COALESCE(body::json ->> 'notAfter', body::json ->> 'validTo') WHERE not_before IS NULL AND not_after IS NULL;
CREATE INDEX IF NOT EXISTS gate_tuple_not_after ON gate_tuple (not_after);
CREATE TABLE IF NOT EXISTS gate_state_change (seq bigint NOT NULL, version bigint NOT NULL, kind text NOT NULL CHECK (kind IN ('subject', 'resource', 'tuple')), type text NOT NULL, id text NOT NULL, op text NOT NULL CHECK (op IN ('put', 'delete')), position bigint, body text, move boolean NOT NULL DEFAULT false, PRIMARY KEY (seq, kind, type, id));
ALTER TABLE gate_state_change ADD COLUMN IF NOT EXISTS move boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS gate_state_change_version ON gate_state_change (version);
ALTER TABLE gate_subject ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_subject FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_resource ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_resource FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_tuple ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_tuple FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_state_change ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_state_change FORCE ROW LEVEL SECURITY;`;
export const RECORD_SYNC = `ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS records bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS records_migrated boolean NOT NULL DEFAULT false;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS subject_position bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS resource_position bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS tuple_position bigint NOT NULL DEFAULT 0;`;
export const RECORD_POLICIES = `IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_subject' AND policyname = 'gate_subject_rw') THEN
    CREATE POLICY gate_subject_rw ON gate_subject FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_resource' AND policyname = 'gate_resource_rw') THEN
    CREATE POLICY gate_resource_rw ON gate_resource FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_tuple' AND policyname = 'gate_tuple_rw') THEN
    CREATE POLICY gate_tuple_rw ON gate_tuple FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_state_change' AND policyname = 'gate_state_change_read') THEN
    CREATE POLICY gate_state_change_read ON gate_state_change FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_state_change' AND policyname = 'gate_state_change_append') THEN
    CREATE POLICY gate_state_change_append ON gate_state_change FOR INSERT TO PUBLIC WITH CHECK (true); END IF;`;
export const SCHEMA = `
CREATE TABLE IF NOT EXISTS gate_doc (name text PRIMARY KEY, body text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS gate_audit (node text NOT NULL DEFAULT '0', seq bigint NOT NULL CHECK (seq > 0), record text NOT NULL, PRIMARY KEY (node, seq));
CREATE TABLE IF NOT EXISTS gate_audit_meta (node text NOT NULL DEFAULT '0', seq bigint NOT NULL, ts text NOT NULL, type text NOT NULL, effect text, subject text, resource text, rules text[] NOT NULL, PRIMARY KEY (node, seq));
CREATE TABLE IF NOT EXISTS gate_anchor (seq bigint PRIMARY KEY, hash text NOT NULL, tsa text NOT NULL, gen_time timestamptz NOT NULL, token bytea NOT NULL, heads text);
CREATE TABLE IF NOT EXISTS gate_audit_segment (node text NOT NULL, seq bigint NOT NULL CHECK (seq > 0), body text NOT NULL, PRIMARY KEY (node, seq));
CREATE TABLE IF NOT EXISTS gate_subject_identity (pseudonym text PRIMARY KEY, id text NOT NULL UNIQUE, key text NOT NULL);
ALTER TABLE gate_audit ADD COLUMN IF NOT EXISTS node text NOT NULL DEFAULT '0';
ALTER TABLE gate_audit_meta ADD COLUMN IF NOT EXISTS node text NOT NULL DEFAULT '0';
ALTER TABLE gate_anchor ADD COLUMN IF NOT EXISTS heads text;
DO $$ DECLARE t text; pk text; BEGIN
  FOREACH t IN ARRAY ARRAY['gate_audit', 'gate_audit_meta'] LOOP
    pk := NULL;
    SELECT conname INTO pk FROM pg_constraint WHERE conrelid = t::regclass AND contype = 'p' AND array_length(conkey, 1) = 1;
    IF pk IS NOT NULL THEN EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I, ADD PRIMARY KEY (node, seq)', t, pk); END IF;
  END LOOP;
END $$;
CREATE TABLE IF NOT EXISTS gate_sync (id int PRIMARY KEY CHECK (id = 1), version bigint NOT NULL DEFAULT 0, performed bigint NOT NULL DEFAULT 0, leader text);
INSERT INTO gate_sync (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
${RECORD_SYNC}
CREATE TABLE IF NOT EXISTS gate_token (jti text PRIMARY KEY, node text NOT NULL, body text NOT NULL, exp bigint NOT NULL, used boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS gate_token_exp ON gate_token (exp);
CREATE TABLE IF NOT EXISTS gate_performed (seq bigint PRIMARY KEY CHECK (seq > 0), node text NOT NULL, body text NOT NULL);
ALTER TABLE gate_performed ADD COLUMN IF NOT EXISTS ref text;
ALTER TABLE gate_performed ADD COLUMN IF NOT EXISTS kind text CHECK (kind IN ('reservation', 'outcome'));
CREATE UNIQUE INDEX IF NOT EXISTS gate_performed_ref ON gate_performed (ref, kind);
${SESSION_TABLE}
CREATE TABLE IF NOT EXISTS gate_blp_mark (session text NOT NULL, subject text NOT NULL, level int NOT NULL CHECK (level BETWEEN 0 AND 3),
  started bigint NOT NULL, seen bigint NOT NULL, PRIMARY KEY (session, subject));
ALTER TABLE gate_blp_mark ADD COLUMN IF NOT EXISTS held_until bigint;
${BLP_SESSION_TABLE}
${RETIRED_TABLE}
${RATE_LIMIT_TABLE}
${RECORD_TABLES}
CREATE INDEX IF NOT EXISTS gate_audit_meta_subject_seq ON gate_audit_meta (subject, seq);
CREATE INDEX IF NOT EXISTS gate_audit_meta_resource_seq ON gate_audit_meta (resource, seq);
CREATE INDEX IF NOT EXISTS gate_audit_meta_type_seq ON gate_audit_meta (type, seq);
CREATE INDEX IF NOT EXISTS gate_audit_meta_rules ON gate_audit_meta USING GIN (rules);
ALTER TABLE gate_doc ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_doc FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_audit ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_audit_meta ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_audit_meta FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_anchor ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_anchor FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_audit_segment ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_audit_segment FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_subject_identity ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_subject_identity FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_sync ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_sync FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_token ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_token FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_performed ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_performed FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_blp_mark ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_blp_mark FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_blp_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_blp_session FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_rate_limit ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_rate_limit FORCE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_doc' AND policyname = 'gate_doc_rw') THEN
    CREATE POLICY gate_doc_rw ON gate_doc FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit' AND policyname = 'gate_audit_read') THEN
    CREATE POLICY gate_audit_read ON gate_audit FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit' AND policyname = 'gate_audit_append') THEN
    CREATE POLICY gate_audit_append ON gate_audit FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit' AND policyname = 'gate_audit_retention') THEN
    CREATE POLICY gate_audit_retention ON gate_audit FOR DELETE TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit_meta' AND policyname = 'gate_audit_meta_rw') THEN
    CREATE POLICY gate_audit_meta_rw ON gate_audit_meta FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_anchor' AND policyname = 'gate_anchor_read') THEN
    CREATE POLICY gate_anchor_read ON gate_anchor FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_anchor' AND policyname = 'gate_anchor_append') THEN
    CREATE POLICY gate_anchor_append ON gate_anchor FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit_segment' AND policyname = 'gate_audit_segment_read') THEN
    CREATE POLICY gate_audit_segment_read ON gate_audit_segment FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit_segment' AND policyname = 'gate_audit_segment_append') THEN
    CREATE POLICY gate_audit_segment_append ON gate_audit_segment FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_audit_segment' AND policyname = 'gate_audit_segment_rekey') THEN
    CREATE POLICY gate_audit_segment_rekey ON gate_audit_segment FOR UPDATE TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_subject_identity' AND policyname = 'gate_subject_identity_rw') THEN
    CREATE POLICY gate_subject_identity_rw ON gate_subject_identity FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_sync' AND policyname = 'gate_sync_rw') THEN
    CREATE POLICY gate_sync_rw ON gate_sync FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_token' AND policyname = 'gate_token_rw') THEN
    CREATE POLICY gate_token_rw ON gate_token FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_performed' AND policyname = 'gate_performed_read') THEN
    CREATE POLICY gate_performed_read ON gate_performed FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_performed' AND policyname = 'gate_performed_append') THEN
    CREATE POLICY gate_performed_append ON gate_performed FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_session' AND policyname = 'gate_session_rw') THEN
    ${SESSION_POLICY} END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_blp_mark' AND policyname = 'gate_blp_mark_rw') THEN
    CREATE POLICY gate_blp_mark_rw ON gate_blp_mark FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_blp_session' AND policyname = 'gate_blp_session_rw') THEN
    ${BLP_SESSION_POLICY} END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_retired' AND policyname = 'gate_retired_read') THEN
    ${RETIRED_POLICY} END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_rate_limit' AND policyname = 'gate_rate_limit_rw') THEN
    ${RATE_LIMIT_POLICY} END IF;
  ${RECORD_POLICIES}
END $$;
ALTER TABLE gate_subject_identity ADD COLUMN IF NOT EXISTS used_at timestamptz;
CREATE INDEX IF NOT EXISTS gate_subject_identity_used ON gate_subject_identity (used_at);
REVOKE UPDATE, DELETE, TRUNCATE ON gate_audit, gate_anchor, gate_performed, gate_retired, gate_audit_segment, gate_state_change FROM CURRENT_USER;
REVOKE DELETE, TRUNCATE ON gate_audit_meta FROM CURRENT_USER;
`;

/** The production service role's privileges (docs/API.md §3.9.1): audit retention remains with the owner; subject mappings
 *  are deliberately erasable through the privacy route, unlike the chained rows that carry their pseudonyms. The service
 *  role rewrites individual world records, but cannot rewrite their append-only change log. */
export const serviceGrants = (role: string): string => `
GRANT SELECT, INSERT, UPDATE ON gate_doc, gate_audit_meta TO ${role};
GRANT SELECT, INSERT ON gate_audit, gate_anchor, gate_performed, gate_retired, gate_state_change TO ${role};
GRANT SELECT ON gate_audit_segment TO ${role};
GRANT SELECT, INSERT, UPDATE, DELETE ON gate_subject_identity TO ${role};
GRANT SELECT, UPDATE ON gate_sync TO ${role};
GRANT SELECT, INSERT, UPDATE, DELETE ON gate_token, gate_session, gate_blp_mark, gate_blp_session, gate_subject, gate_resource, gate_tuple, gate_rate_limit TO ${role};`;

/** Every gate table, as scripts/ops/backup.sh and restore.sh list them: the backup role reads them all. */
export const BACKUP_TABLES = ['gate_doc', 'gate_audit', 'gate_audit_meta', 'gate_anchor', 'gate_audit_segment', 'gate_subject_identity', 'gate_sync', 'gate_token', 'gate_performed', 'gate_session', 'gate_blp_mark', 'gate_blp_session', 'gate_retired', 'gate_subject', 'gate_resource', 'gate_tuple', 'gate_state_change', 'gate_rate_limit'] as const;
/** The backup role's privileges (deploy/k8s gate-migrate): read only; pg_dump also needs BYPASSRLS on the role. */
export const backupGrants = (role: string): string => `
GRANT SELECT ON ${BACKUP_TABLES.join(', ')} TO ${role};`;
