import type { ReplayStore } from '../../packages/sdk/src/assertion.ts';

export interface ReplayDatabase {
  query(text: string, values?: unknown[]): Promise<{ rowCount: number | null }>;
}

/** Run once as the schema owner; backends need SELECT, INSERT, UPDATE and DELETE on this table only. */
export const replaySchema = `CREATE TABLE IF NOT EXISTS example_assertion_replay (
  backend TEXT NOT NULL, nonce TEXT NOT NULL, expires_at BIGINT NOT NULL,
  PRIMARY KEY (backend, nonce)
);
CREATE INDEX IF NOT EXISTS example_assertion_replay_expiry ON example_assertion_replay (expires_at)`;

/** Every replica of one audience uses the same backend name and database. */
export class PostgresReplayStore implements ReplayStore {
  private readonly db: ReplayDatabase;
  private readonly backend: string;
  constructor(db: ReplayDatabase, backend: string) {
    if (!backend) throw new TypeError('backend is required');
    this.db = db; this.backend = backend;
  }
  async spend(nonce: string, expiresAt: number): Promise<boolean> {
    if (!nonce || !Number.isSafeInteger(expiresAt)) throw new TypeError('Invalid replay entry');
    const result = await this.db.query(`INSERT INTO example_assertion_replay (backend, nonce, expires_at)
      VALUES ($1, $2, $3) ON CONFLICT (backend, nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at
      WHERE example_assertion_replay.expires_at < floor(extract(epoch FROM clock_timestamp()))`, [this.backend, nonce, expiresAt]);
    return result.rowCount === 1;
  }
  /** Schedule outside the request path; failure never makes a spent nonce fresh. */
  async prune(): Promise<void> {
    await this.db.query('DELETE FROM example_assertion_replay WHERE backend = $1 AND expires_at < floor(extract(epoch FROM clock_timestamp()))', [this.backend]);
  }
}
