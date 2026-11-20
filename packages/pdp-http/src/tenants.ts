// Tenant stores stay separate: a partition never filters an authorization graph or shares a security namespace.
import { createServer as httpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { existsSync, readFileSync, readlinkSync, realpathSync } from 'node:fs';
import { resolve, dirname, basename, sep } from 'node:path';
import { createServer, type PdpServer, type ServerOptions } from './server.ts';
import { failure, HttpError, json } from './http.ts';
import { parseReplicaKeys } from './replica-protocol.ts';
import { parsePins } from './replica.ts';
import { decodeSeal } from './tokens.ts';

const ID = /^[a-z][a-z0-9-]{0,62}$/;
const fields = new Set(['dataDir', 'worldDir', 'databaseUrl', 'signingKeySeal', 'signingKeySealPrevious', 'auditCheckpointMigration', 'replicaOf', 'replicaKey', 'replicaPins', 'replicaKeys', 'replicaCaFile', 'advertiseUrl', 'publicOrigin']);

function physicalPath(path: string, hops = 0): string {
  if (hops > 64) throw new Error('Tenant data directory symlink chain is too deep');
  if (existsSync(path)) return realpathSync(path);
  let target: string | undefined;
  try { target = readlinkSync(path); } catch (err) {
    if (!['ENOENT', 'EINVAL'].includes((err as NodeJS.ErrnoException).code ?? '')) throw err;
  }
  if (target !== undefined) return physicalPath(resolve(dirname(path), target), hops + 1);
  return resolve(physicalPath(dirname(path), hops + 1), basename(path));
}

function isolation(tenants: ReadonlyMap<string, ServerOptions>): void {
  const dirs: string[] = [], databases = new Set<string>(), keys = new Map<string, string>();
  for (const [id, config] of tenants) {
    if (!ID.test(id) || !config.dataDir || !config.worldDir) throw new Error('Every tenant needs an id, dataDir and worldDir');
    const dir = physicalPath(resolve(config.dataDir));
    if (dirs.some((old) => dir === old || dir.startsWith(old.endsWith(sep) ? old : old + sep) || old.startsWith(dir.endsWith(sep) ? dir : dir + sep))) throw new Error('Tenant data directories must not overlap');
    dirs.push(dir);
    if (config.databaseUrl) {
      let url: URL;
      try { url = new URL(config.databaseUrl); } catch { throw new Error('Invalid tenant database URL'); }
      if (!['postgres:', 'postgresql:'].includes(url.protocol)) throw new Error('Invalid tenant database URL');
      const database = `${url.hostname.toLowerCase()}:${url.port || '5432'}${decodeURIComponent(url.pathname)}`;
      if (databases.has(database)) throw new Error('Tenants must use separate databases');
      databases.add(database);
      if (!config.signingKeySeal) throw new Error('Every database tenant needs its own signingKeySeal');
    }
    const secrets = [decodeSeal(config.signingKeySeal), decodeSeal(config.signingKeySealPrevious, 'signingKeySealPrevious'),
      decodeSeal(config.replicaKey, 'replicaKey'), ...config.replicaKeys?.values() ?? []];
    for (const secret of secrets) if (secret) {
      const key = secret.toString('hex');
      if (keys.has(key) && keys.get(key) !== id) throw new Error('Tenant security keys must be distinct');
      keys.set(key, id);
    }
  }
}

export function tenantSelection(raw: string | undefined, names: readonly string[]): string[] {
  const selected = raw === undefined ? [...names] : raw.split(',').map((s) => s.trim());
  if (!selected.length || selected.some((id) => !ID.test(id) || !names.includes(id)) || new Set(selected).size !== selected.length) {
    throw new Error('GATE_SERVE_TENANTS must list distinct tenant ids from GATE_TENANTS_FILE');
  }
  return selected;
}

/** Parse without reporting values: the manifest contains database and replica credentials. */
export function tenantManifest(raw: string): Map<string, ServerOptions> {
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error('GATE_TENANTS_FILE must contain a JSON object'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Object.keys(parsed).length) throw new Error('GATE_TENANTS_FILE must contain a nonempty tenant map');
  const tenants = new Map<string, ServerOptions>();
  for (const [id, entry] of Object.entries(parsed)) {
    if (!ID.test(id) || !entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Invalid tenant manifest entry');
    const config = entry as Record<string, string>;
    if (Object.entries(config).some(([key, value]) => !fields.has(key) || typeof value !== 'string' || !value.trim())) throw new Error('Invalid tenant manifest field');
    if (!config.dataDir || !config.worldDir) throw new Error('Every tenant needs dataDir and worldDir');
    const { replicaKeys, replicaPins, ...options } = config;
    tenants.set(id, { ...options, replicaKeys: parseReplicaKeys(replicaKeys), replicaPins: parsePins(replicaPins) });
  }
  isolation(tenants);
  return tenants;
}

export function tenantConfigFromEnv(env: NodeJS.ProcessEnv): { tenants: Map<string, ServerOptions>; selected: string[] } | undefined {
  if (!env.GATE_TENANTS_FILE) {
    if (env.GATE_SERVE_TENANTS !== undefined) throw new Error('GATE_SERVE_TENANTS needs GATE_TENANTS_FILE');
    return undefined;
  }
  const tenants = tenantManifest(readFileSync(env.GATE_TENANTS_FILE, 'utf8'));
  return { tenants, selected: tenantSelection(env.GATE_SERVE_TENANTS, [...tenants.keys()]) };
}

export function createTenantServer(options: ServerOptions, tenants: ReadonlyMap<string, ServerOptions>, selected: readonly string[]): PdpServer {
  isolation(tenants);
  tenantSelection(selected.join(','), [...tenants.keys()]);
  const children = new Map<string, PdpServer>();
  let base = '', ready = false;
  const handle = (req: IncomingMessage, res: ServerResponse): void => {
    const id = req.headers['x-gate-tenant'];
    const duplicates = req.rawHeaders.filter((_, i) => i % 2 === 0 && req.rawHeaders[i]!.toLowerCase() === 'x-gate-tenant').length;
    if (typeof id !== 'string' || !ID.test(id) || duplicates !== 1) { failure(res, new HttpError(400, 'tenant_required', 'Supply one X-Qadamar-Tenant header')); return; }
    if (!selected.includes(id)) { failure(res, new HttpError(421, 'tenant_not_served', 'This node does not serve the requested tenant; route to its partition')); return; }
    if (!ready) { json(res, { error: 'unavailable' }, 503); return; }
    children.get(id)!.handle(req, res);
  };
  const server = options.tls ? httpsServer({ ...options.tls, minVersion: 'TLSv1.2' }, handle) : httpServer(handle);
  server.requestTimeout = 30_000; server.headersTimeout = 10_000;
  const each = async (fn: (child: PdpServer) => Promise<void>): Promise<void> => { for (const child of children.values()) await fn(child); };
  const close = async (): Promise<void> => {
    ready = false;
    if (server.listening) await new Promise<void>((done) => { server.close(() => done()); server.closeIdleConnections(); });
    await each((child) => child.close()); children.clear();
  };
  return {
    get url() { return base; }, handle, close,
    anchor: () => each((child) => child.anchor()), exportAudit: () => each((child) => child.exportAudit()),
    notifyExpired: () => each((child) => child.notifyExpired()), flushTraces: () => each((child) => child.flushTraces()),
    listen: async (port = options.port ?? 8787, host = options.host ?? '127.0.0.1'): Promise<void> => {
      try {
        await new Promise<void>((done, fail) => {
          server.once('error', fail);
          server.listen(port, host, () => { server.off('error', fail); done(); });
        });
        const address = server.address();
        if (!address || typeof address === 'string') throw new Error('No partition address');
        base = `${options.tls ? 'https' : 'http'}://${host.includes(':') ? `[${host}]` : host}:${address.port}`;
        for (const id of selected) {
          const config = tenants.get(id)!;
          const child = createServer({ ...options, databaseUrl: undefined, replicaOf: undefined, replicaKey: undefined, replicaKeys: undefined,
            replicaPins: undefined,
            signingKeySeal: undefined, signingKeySealPrevious: undefined, auditCheckpointMigration: undefined,
            ...config, tenantId: id });
          children.set(id, child);
          await child.listen(port, host, config.publicOrigin ?? options.publicOrigin ?? base);
        }
        ready = true;
      } catch (err) { await close(); throw err; }
    },
  };
}
