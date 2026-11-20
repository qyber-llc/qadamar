-- The PostgreSQL SCHEMA of release 0.8.3 (packages/pdp-http/src/postgres-schema.ts at v0.8.3), for the upgrade test.

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
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS records bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS records_migrated boolean NOT NULL DEFAULT false;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS subject_position bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS resource_position bigint NOT NULL DEFAULT 0;
ALTER TABLE gate_sync ADD COLUMN IF NOT EXISTS tuple_position bigint NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS gate_token (jti text PRIMARY KEY, node text NOT NULL, body text NOT NULL, exp bigint NOT NULL, used boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS gate_token_exp ON gate_token (exp);
CREATE TABLE IF NOT EXISTS gate_performed (seq bigint PRIMARY KEY CHECK (seq > 0), node text NOT NULL, body text NOT NULL);
ALTER TABLE gate_performed ADD COLUMN IF NOT EXISTS ref text;
ALTER TABLE gate_performed ADD COLUMN IF NOT EXISTS kind text CHECK (kind IN ('reservation', 'outcome'));
CREATE UNIQUE INDEX IF NOT EXISTS gate_performed_ref ON gate_performed (ref, kind);
CREATE TABLE IF NOT EXISTS gate_session (id text PRIMARY KEY, body text NOT NULL, method text NOT NULL, oidc_sub text, oidc_sid text, created bigint NOT NULL, touched bigint NOT NULL);
CREATE INDEX IF NOT EXISTS gate_session_touched ON gate_session (touched);
ALTER TABLE gate_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_session FORCE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS gate_blp_mark (session text NOT NULL, subject text NOT NULL, level int NOT NULL CHECK (level BETWEEN 0 AND 3),
  started bigint NOT NULL, seen bigint NOT NULL, PRIMARY KEY (session, subject));
CREATE TABLE IF NOT EXISTS gate_retired (type text NOT NULL, id text NOT NULL, version bigint NOT NULL, retired_at text NOT NULL, node text NOT NULL, PRIMARY KEY (type, id, version));
ALTER TABLE gate_retired ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_retired FORCE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS gate_rate_limit (key text PRIMARY KEY, tokens double precision NOT NULL, at double precision NOT NULL, leased double precision NOT NULL);
ALTER TABLE gate_rate_limit ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_rate_limit FORCE ROW LEVEL SECURITY;
CREATE TABLE IF NOT EXISTS gate_subject (type text NOT NULL, id text NOT NULL, position bigint NOT NULL, state_version bigint NOT NULL, body text NOT NULL, PRIMARY KEY (type, id));
CREATE INDEX IF NOT EXISTS gate_subject_position ON gate_subject (position);
CREATE TABLE IF NOT EXISTS gate_resource (type text NOT NULL, id text NOT NULL, position bigint NOT NULL, state_version bigint NOT NULL, body text NOT NULL, PRIMARY KEY (type, id));
CREATE INDEX IF NOT EXISTS gate_resource_position ON gate_resource (position);
CREATE TABLE IF NOT EXISTS gate_tuple (id text PRIMARY KEY, position bigint NOT NULL, state_version bigint NOT NULL, object_type text NOT NULL, object_id text NOT NULL, subject_type text NOT NULL, subject_id text NOT NULL, body text NOT NULL);
CREATE INDEX IF NOT EXISTS gate_tuple_position ON gate_tuple (position);
CREATE INDEX IF NOT EXISTS gate_tuple_object ON gate_tuple (object_type, object_id);
CREATE INDEX IF NOT EXISTS gate_tuple_subject ON gate_tuple (subject_type, subject_id);
CREATE TABLE IF NOT EXISTS gate_state_change (seq bigint NOT NULL, version bigint NOT NULL, kind text NOT NULL CHECK (kind IN ('subject', 'resource', 'tuple')), type text NOT NULL, id text NOT NULL, op text NOT NULL CHECK (op IN ('put', 'delete')), position bigint, body text, move boolean NOT NULL DEFAULT false, PRIMARY KEY (seq, kind, type, id));
ALTER TABLE gate_state_change ADD COLUMN IF NOT EXISTS move boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS gate_state_change_version ON gate_state_change (version);
ALTER TABLE gate_subject ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_subject FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_resource ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_resource FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_tuple ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_tuple FORCE ROW LEVEL SECURITY;
ALTER TABLE gate_state_change ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_state_change FORCE ROW LEVEL SECURITY;
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
    CREATE POLICY gate_session_rw ON gate_session FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_blp_mark' AND policyname = 'gate_blp_mark_rw') THEN
    CREATE POLICY gate_blp_mark_rw ON gate_blp_mark FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_retired' AND policyname = 'gate_retired_read') THEN
    CREATE POLICY gate_retired_read ON gate_retired FOR SELECT TO PUBLIC USING (true); CREATE POLICY gate_retired_append ON gate_retired FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_rate_limit' AND policyname = 'gate_rate_limit_rw') THEN
    CREATE POLICY gate_rate_limit_rw ON gate_rate_limit FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_subject' AND policyname = 'gate_subject_rw') THEN
    CREATE POLICY gate_subject_rw ON gate_subject FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_resource' AND policyname = 'gate_resource_rw') THEN
    CREATE POLICY gate_resource_rw ON gate_resource FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_tuple' AND policyname = 'gate_tuple_rw') THEN
    CREATE POLICY gate_tuple_rw ON gate_tuple FOR ALL TO PUBLIC USING (true) WITH CHECK (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_state_change' AND policyname = 'gate_state_change_read') THEN
    CREATE POLICY gate_state_change_read ON gate_state_change FOR SELECT TO PUBLIC USING (true); END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'gate_state_change' AND policyname = 'gate_state_change_append') THEN
    CREATE POLICY gate_state_change_append ON gate_state_change FOR INSERT TO PUBLIC WITH CHECK (true); END IF;
END $$;
REVOKE UPDATE, DELETE, TRUNCATE ON gate_audit, gate_anchor, gate_performed, gate_retired, gate_audit_segment, gate_state_change FROM CURRENT_USER;
REVOKE DELETE, TRUNCATE ON gate_audit_meta FROM CURRENT_USER;
