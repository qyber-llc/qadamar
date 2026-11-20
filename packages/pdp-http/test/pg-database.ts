// A throwaway PostgreSQL database per test (TEST_DATABASE_URL: a superuser URL), so test files running in parallel never
// share tables or advisory locks.
import { randomBytes } from 'node:crypto';
import type { TestContext } from 'node:test';
import pg from 'pg';

export const admin = process.env.TEST_DATABASE_URL;
export const skip = admin ? false : 'TEST_DATABASE_URL is not set';

export async function throwawayDatabase(t: TestContext, prefix: string): Promise<{ url: string; sql: (text: string, values?: unknown[]) => Promise<pg.QueryResult> }> {
  const name = `${prefix}_${randomBytes(4).toString('hex')}`;
  const root = new pg.Client({ connectionString: admin }); await root.connect();
  await root.query(`CREATE DATABASE ${name}`);
  await root.end();
  const u = new URL(admin!); u.pathname = `/${name}`;
  const url = u.toString();
  t.after(async () => {
    const c = new pg.Client({ connectionString: admin }); await c.connect();
    await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    await c.end();
  });
  const sql = async (text: string, values?: unknown[]): Promise<pg.QueryResult> => {
    const c = new pg.Client({ connectionString: url }); await c.connect();
    try { return await c.query(text, values); } finally { await c.end(); }
  };
  return { url, sql };
}
