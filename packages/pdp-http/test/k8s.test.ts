// Checks the managed-offer manifests (deploy/k8s) as kustomize renders them. Opt-in: GATE_K8S_TEST=1, with kubectl on
// the PATH and a reachable context (GATE_K8S_CONTEXT, default orbstack) used only to convert YAML to JSON offline
// (client-side dry run, nothing is sent to the cluster).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { BACKUP_TABLES, RETIRED_POLICY, RETIRED_TABLE, SCHEMA, SESSION_POLICY, SESSION_TABLE, backupGrants, serviceGrants } from '../src/postgres.ts';

const skip = process.env.GATE_K8S_TEST === '1' ? false : 'set GATE_K8S_TEST=1 to check the Kubernetes manifests (needs kubectl)';
const root = resolve(import.meta.dirname, '../../..');
const context = process.env.GATE_K8S_CONTEXT ?? 'orbstack';
interface Container { name: string; image: string; securityContext?: Record<string, unknown>; resources?: { requests?: object; limits?: object }; args?: string[];
  env?: { name: string; value?: string; valueFrom?: { secretKeyRef?: { name: string; key: string } } }[];
  readinessProbe?: { httpGet?: { path: string } }; livenessProbe?: object; startupProbe?: object }
interface PodSpec { securityContext?: Record<string, unknown>; automountServiceAccountToken?: boolean; containers: Container[]; initContainers?: Container[];
  topologySpreadConstraints?: object[] }
interface Resource { kind: string; metadata: { name: string; labels?: Record<string, string>; annotations?: Record<string, string> }; data?: Record<string, string>;
  spec?: Record<string, unknown> & { template?: { metadata?: { annotations?: Record<string, string> }; spec: PodSpec };
    jobTemplate?: { spec: { template: { spec: PodSpec } } }; policyTypes?: string[]; podSelector?: object; tls?: object[] } }

function render(dir: string): Resource[] {
  const yaml = execFileSync('kubectl', ['kustomize', resolve(root, dir)], { encoding: 'utf8' });
  const json = execFileSync('kubectl', ['--context', context, 'create', '--dry-run=client', '--validate=false', '-o', 'json', '-f', '-'],
    { input: yaml, encoding: 'utf8' });
  // one pretty-printed object per resource, each closing brace at column 0
  return JSON.parse(`[${json.trim().replace(/\n\}\n\{/g, '\n},\n{')}]`) as Resource[];
}
const podSpec = (r: Resource): PodSpec | undefined => r.spec?.template?.spec ?? r.spec?.jobTemplate?.spec.template.spec;
const secretVariables = ['DATABASE_URL', 'SIGNING_KEY_SEAL', 'METRICS_TOKEN', 'OWNER_DATABASE_URL', 'BACKUP_DATABASE_URL', 'POSTGRES_PASSWORD',
  'OIDC_CLIENT_SECRET', 'BREAK_GLASS_WEBHOOK_SECRET', 'BACKUP_ENCRYPTION_KEY', 'SIEM_HMAC_SECRET'];
const config = (resources: Resource[]): Record<string, string> => resources.find((r) => r.kind === 'ConfigMap' && r.metadata.name.startsWith('gate-config'))?.data ?? {};

function assertRestricted(resources: Resource[]): void {
  const workloads = resources.filter(podSpec);
  assert.ok(workloads.length >= 3, 'Deployment, Job and CronJob at least');
  for (const workload of workloads) {
    const spec = podSpec(workload)!; const where = `${workload.kind}/${workload.metadata.name}`;
    assert.equal(spec.securityContext?.runAsNonRoot, true, `${where} runAsNonRoot`);
    assert.deepEqual(spec.securityContext?.seccompProfile, { type: 'RuntimeDefault' }, `${where} seccomp`);
    assert.equal(spec.automountServiceAccountToken, false, `${where} mounts no API token`);
    for (const container of [...spec.containers, ...(spec.initContainers ?? [])]) {
      const at = `${where} container ${container.name}`;
      assert.equal(container.securityContext?.allowPrivilegeEscalation, false, `${at} privilege escalation`);
      assert.equal(container.securityContext?.readOnlyRootFilesystem, true, `${at} read-only root`);
      assert.equal(container.securityContext?.privileged, false, `${at} unprivileged`);
      assert.deepEqual((container.securityContext?.capabilities as { drop?: string[] } | undefined)?.drop, ['ALL'], `${at} drops all capabilities`);
      assert.ok(container.resources?.requests && container.resources.limits, `${at} requests and limits`);
      for (const variable of container.env ?? []) {
        if (secretVariables.includes(variable.name)) assert.ok(variable.valueFrom?.secretKeyRef && variable.value === undefined, `${at} ${variable.name} from a Secret`);
      }
    }
  }
  const namespace = resources.find((r) => r.kind === 'Namespace');
  assert.equal(namespace?.metadata.labels?.['pod-security.kubernetes.io/enforce'], 'restricted');
  assert.ok(!resources.some((r) => r.kind === 'Secret'), 'Secrets are referenced, never defined in the manifests');
  // a Deployment (active/standby) or, in cluster mode, a StatefulSet (stable node ids)
  const gate = resources.find((r) => (r.kind === 'Deployment' || r.kind === 'StatefulSet') && r.metadata.name === 'gate')!;
  const server = gate.spec!.template!.spec.containers[0]!;
  assert.equal(gate.spec!.replicas, 2);
  assert.equal(server.readinessProbe?.httpGet?.path, '/readyz', 'only the active node is ready');
  assert.ok(server.livenessProbe && server.startupProbe);
  assert.ok(gate.spec!.template!.spec.topologySpreadConstraints?.length);
  assert.equal(gate.spec!.template!.metadata?.annotations?.['prometheus.io/scrape'], 'true');
  assert.equal(gate.spec!.template!.spec.initContainers, undefined, 'no shared DATA_DIR copy: security material lives in PostgreSQL');
  assert.equal(config(resources).GATE_PROFILE, 'production');
  assert.equal(config(resources).SOD_HISTORY, 'server');
  assert.equal(config(resources).BLP_SESSION_REQUIRED, 'true');
  assert.equal(config(resources).DATABASE_TLS, 'verify-full');
  assert.equal(config(resources).CLOCK, undefined, 'production refuses a pinned clock');
  for (const name of ['DATABASE_URL', 'SIGNING_KEY_SEAL', 'METRICS_TOKEN', 'OIDC_ISSUER', 'OIDC_CLIENT_SECRET', 'TSA_URL', 'TSA_CA_FILE', 'BREAK_GLASS_WEBHOOK', 'BREAK_GLASS_WEBHOOK_SECRET']) {
    assert.ok(server.env?.some((v) => v.name === name && v.valueFrom?.secretKeyRef), `${name} from a Secret`);
  }
  for (const workload of resources.filter((r) => ['Deployment', 'StatefulSet', 'Job', 'CronJob'].includes(r.kind))) {
    const containers = podSpec(workload)?.containers ?? [];
    for (const container of containers) {
      // the PostgreSQL clients (decision replicas have no database URL)
      if (!['gate', 'migrate', 'backup'].includes(container.name) || !container.env?.some((v) => /DATABASE_URL$/.test(v.name))) continue;
      for (const name of ['DATABASE_TLS_CA_FILE', 'DATABASE_TLS_CERT_FILE', 'DATABASE_TLS_KEY_FILE']) {
        assert.ok(container.env?.some((v) => v.name === name && v.valueFrom?.secretKeyRef?.name === 'gate-postgres-tls' && v.valueFrom.secretKeyRef.key === name),
          `${workload.metadata.name}: ${name} is a path-valued key of the optional database TLS Secret`);
      }
    }
  }
  assert.ok(resources.some((r) => r.kind === 'PodDisruptionBudget'));
  const backup = resources.find((r) => r.kind === 'CronJob' && r.metadata.name === 'gate-backup');
  assert.ok(backup?.spec?.jobTemplate?.spec.template.spec.containers[0]!.env?.some((v) => v.name === 'BACKUP_ENCRYPTION_KEY' && v.valueFrom?.secretKeyRef),
    'backup.sh refuses to run without BACKUP_ENCRYPTION_KEY');
  const deny = resources.find((r) => r.kind === 'NetworkPolicy' && r.metadata.name === 'default-deny');
  assert.deepEqual(deny?.spec?.policyTypes, ['Ingress', 'Egress']);
  assert.deepEqual(deny?.spec?.podSelector, {});
}

test('base: restricted workloads, probes, secrets by reference, default-deny, TLS ingress', { skip }, () => {
  const resources = render('deploy/k8s/base');
  assertRestricted(resources);
  assert.ok(resources.find((r) => r.kind === 'Ingress')?.spec?.tls?.length, 'Ingress with TLS');
  assert.match(config(resources).TRUSTED_PROXIES ?? '', /^[0-9a-f.:/,]+$/, 'TRUSTED_PROXIES names the ingress controller range (PARAMETER)');
});

test('local overlay: the same guarantees, in-cluster PostgreSQL, no Ingress, marked local test only', { skip }, () => {
  const resources = render('deploy/k8s/overlays/local');
  assertRestricted(resources);
  assert.ok(resources.some((r) => r.kind === 'StatefulSet' && r.metadata.name === 'postgres'));
  assert.ok(!resources.some((r) => r.kind === 'Ingress'));
  assert.ok(resources.every((r) => r.metadata.annotations?.['qadamar.example/environment'] === 'local test only'));
  // the production profile for real: TLS served by Qadamar, test IdP / TSA / webhook in the namespace, no proxy trusted
  assert.equal(config(resources).TLS_CERT_FILE, '/etc/gate/tls/tls.crt');
  assert.equal(config(resources).DATABASE_TLS_CA_FILE, '/etc/gate/postgres/ca.crt');
  const postgres = resources.find((r) => r.kind === 'StatefulSet' && r.metadata.name === 'postgres')!;
  assert.ok(postgres.spec?.template?.spec.containers[0]?.args?.includes('ssl=on'), 'local PostgreSQL exercises verified TLS');
  assert.match(readFileSync(resolve(root, 'scripts/managed/local-test-pki.sh'), 'utf8'), /subjectAltName=DNS:postgres,DNS:postgres\.\$ns\.svc/, 'the database certificate names its Service hostname');
  assert.equal(config(resources).TRUSTED_PROXIES, '');
  for (const name of ['test-idp', 'test-tsa', 'test-webhook']) {
    assert.ok(resources.some((r) => r.kind === 'Deployment' && r.metadata.name === name), name);
    assert.ok(resources.some((r) => r.kind === 'Service' && r.metadata.name === name), `${name} Service`);
  }
  for (const workload of resources.filter(podSpec)) {
    for (const container of podSpec(workload)!.containers) assert.equal((container as { imagePullPolicy?: string }).imagePullPolicy, 'Never', `${workload.metadata.name}: local images only`);
  }
});

test('cluster overlay: a StatefulSet with stable node ids, the leader reachable from followers, no Deployment', { skip }, () => {
  const resources = render('deploy/k8s/overlays/local-cluster');
  assertRestricted(resources);
  assert.equal(config(resources).GATE_CLUSTER, 'true');
  assert.ok(!resources.some((r) => r.kind === 'Deployment' && r.metadata.name === 'gate'), 'the Deployment is replaced');
  const nodes = resources.find((r) => r.kind === 'StatefulSet' && r.metadata.name === 'gate')!;
  assert.equal(nodes.spec?.serviceName, 'gate-nodes');
  const headless = resources.find((r) => r.kind === 'Service' && r.metadata.name === 'gate-nodes');
  assert.equal(headless?.spec?.clusterIP, 'None');
  const env = nodes.spec!.template!.spec.containers[0]!.env ?? [];
  assert.deepEqual(env.find((v) => v.name === 'GATE_NODE_ID')?.valueFrom, { fieldRef: { fieldPath: 'metadata.name' } }, 'the pod name: gate-0, gate-1');
  assert.equal(env.find((v) => v.name === 'GATE_ADVERTISE_URL')?.value, '$(GATE_NODE_SCHEME)://$(GATE_NODE_ID).gate-nodes.$(POD_NAMESPACE).svc:8787');
  assert.equal(env.find((v) => v.name === 'GATE_NODE_SCHEME')?.value, 'https', 'the local nodes serve TLS themselves');
  const index = (name: string) => env.findIndex((v) => v.name === name);
  for (const name of ['GATE_NODE_SCHEME', 'GATE_NODE_ID', 'POD_NAMESPACE']) assert.ok(index(name) >= 0 && index(name) < index('GATE_ADVERTISE_URL'), `${name} is defined before GATE_ADVERTISE_URL uses it`);
  type Peer = { podSelector?: { matchLabels?: Record<string, string> } };
  type Rule = { from?: Peer[]; to?: Peer[]; ports?: { port: number }[] };
  const rules = (name: string, key: 'ingress' | 'egress') => (resources.find((r) => r.kind === 'NetworkPolicy' && r.metadata.name === name)?.spec?.[key] ?? []) as Rule[];
  const gatePods = (peers: Peer[] = []) => peers.some((p) => p.podSelector?.matchLabels?.['app.kubernetes.io/name'] === 'gate' && p.podSelector.matchLabels['app.kubernetes.io/component'] === 'server');
  assert.ok(rules('gate-ingress', 'ingress').some((r) => gatePods(r.from) && r.ports?.some((p) => p.port === 8787)), 'followers may connect to the leader');
  assert.ok(rules('gate-egress-database', 'egress').some((r) => gatePods(r.to) && r.ports?.some((p) => p.port === 8787)), 'and leave their pod for it');
  assert.match(readFileSync(resolve(root, 'scripts/managed/local-test-pki.sh'), 'utf8'), /DNS:\*\.gate-nodes\.\$ns\.svc/, 'the test certificate names every node');
});

test('sovereign-uae overlay: production profile, TLS everywhere, no secret values, egress allow-list, digests, in-country', { skip }, () => {
  const resources = render('deploy/k8s/overlays/sovereign-uae');
  assertRestricted(resources);
  const yaml = execFileSync('kubectl', ['kustomize', resolve(root, 'deploy/k8s/overlays/sovereign-uae')], { encoding: 'utf8' });
  assert.doesNotMatch(yaml, /:\/\/[^\s/:@]+:[^\s/@]+@/, 'no credentials in any URL');
  assert.doesNotMatch(yaml, /sslmode|sslrootcert|PGSSL|gate-db-ca/, 'one database TLS mechanism: DATABASE_TLS and Secret gate-postgres-tls');
  assert.equal(config(resources).GATE_CLUSTER, 'true');
  assert.equal(config(resources).TLS_CERT_FILE, '/etc/gate/tls/tls.crt', 'the Qadamar pods serve TLS (replicas and ingress reach them over https)');
  assert.match(config(resources).PUBLIC_ORIGIN ?? '', /^https:\/\//);
  assert.ok(resources.find((r) => r.kind === 'Ingress')?.spec?.tls?.length, 'Ingress with TLS');
  type Affinity = { nodeAffinity?: { requiredDuringSchedulingIgnoredDuringExecution?: { nodeSelectorTerms: { matchExpressions: { key: string }[] }[] } } };
  for (const workload of resources.filter(podSpec)) {
    const spec = podSpec(workload)! as PodSpec & { affinity?: Affinity; volumes?: { name: string; secret?: { secretName: string } }[] };
    const where = `${workload.kind}/${workload.metadata.name}`;
    assert.equal(workload.metadata.labels?.['qadamar.example/data-residency'], 'AE', `${where} data-residency label`);
    const keys = spec.affinity?.nodeAffinity?.requiredDuringSchedulingIgnoredDuringExecution?.nodeSelectorTerms.flatMap((t) => t.matchExpressions.map((e) => e.key)) ?? [];
    assert.ok(keys.includes('topology.kubernetes.io/region') && keys.includes('topology.kubernetes.io/zone'), `${where} required in-country node affinity`);
    for (const container of [...spec.containers, ...(spec.initContainers ?? [])]) {
      assert.match(container.image, /@sha256:[0-9a-f]{64}$/, `${where} ${container.name} image by digest`);
      // every container that connects to PostgreSQL does so with DATABASE_TLS=verify-full (config, checked above) against
      // the CA of the one database TLS Secret, required here and mounted at the path its DATABASE_TLS_CA_FILE names
      if (container.env?.some((v) => /DATABASE_URL$/.test(v.name))) {
        const env = container.env as { name: string; valueFrom?: { secretKeyRef?: { name: string }; configMapKeyRef?: { key: string } } }[];
        assert.ok(!env.some((v) => /^PGSSL/.test(v.name)), `${where} ${container.name}: no libpq TLS override beside DATABASE_TLS`);
        assert.ok(env.some((v) => v.name === 'DATABASE_TLS_CA_FILE' && v.valueFrom?.secretKeyRef?.name === 'gate-postgres-tls'), `${where} ${container.name} DATABASE_TLS_CA_FILE`);
        assert.ok(container.name === 'gate' || env.some((v) => v.name === 'DATABASE_TLS' && v.valueFrom?.configMapKeyRef?.key === 'DATABASE_TLS'), `${where} ${container.name} DATABASE_TLS`);
        const volume = spec.volumes?.find((v) => v.secret?.secretName === 'gate-postgres-tls') as { name: string; secret: { optional?: boolean } } | undefined;
        assert.equal(volume?.secret.optional, false, `${where} requires the database CA Secret`);
        const mounts = (container as Container & { volumeMounts?: { name: string; mountPath: string }[] }).volumeMounts ?? [];
        assert.ok(mounts.some((m) => m.name === volume!.name && m.mountPath === '/etc/gate/postgres'), `${where} mounts the database CA at /etc/gate/postgres`);
      }
    }
  }
  const nodes = resources.find((r) => r.kind === 'StatefulSet' && r.metadata.name === 'gate')!;
  const server = nodes.spec!.template!.spec.containers[0]! as Container & { readinessProbe?: { httpGet?: { scheme?: string } } };
  assert.equal(server.readinessProbe?.httpGet?.scheme, 'HTTPS');
  assert.equal(server.env?.find((v) => v.name === 'GATE_NODE_SCHEME')?.value, 'https');
  const zoneSpread = (r: Resource) => (r.spec!.template!.spec.topologySpreadConstraints as { topologyKey: string; whenUnsatisfiable: string }[]).find((c) => c.topologyKey === 'topology.kubernetes.io/zone');
  for (const name of ['gate', 'gate-replica']) {
    const set = resources.find((r) => r.kind === 'StatefulSet' && r.metadata.name === name)!;
    assert.equal(zoneSpread(set)?.whenUnsatisfiable, 'DoNotSchedule', `${name} spread across zones`);
    assert.ok(resources.some((r) => r.kind === 'PodDisruptionBudget' && (r.spec?.selector as { matchLabels: Record<string, string> }).matchLabels['app.kubernetes.io/component'] === (name === 'gate' ? 'server' : 'replica')), `${name} PDB`);
  }
  const replica = resources.find((r) => r.kind === 'StatefulSet' && r.metadata.name === 'gate-replica')!;
  assert.ok((replica.spec?.volumeClaimTemplates as { spec: { storageClassName?: string } }[])[0]!.spec.storageClassName, 'replica volumes on a named in-country StorageClass');
  assert.ok((resources.find((r) => r.kind === 'PersistentVolumeClaim' && r.metadata.name === 'gate-backups')?.spec as { storageClassName?: string }).storageClassName);
  const hpa = resources.find((r) => r.kind === 'HorizontalPodAutoscaler');
  assert.deepEqual((hpa?.spec as { scaleTargetRef: object }).scaleTargetRef, { apiVersion: 'apps/v1', kind: 'StatefulSet', name: 'gate-replica' });
  // egress: default deny, then only named destinations on named ports; no rule open to any address
  type Peer = { ipBlock?: { cidr: string }; podSelector?: object; namespaceSelector?: object };
  for (const policy of resources.filter((r) => r.kind === 'NetworkPolicy' && (r.spec?.policyTypes ?? []).includes('Egress') && r.metadata.name !== 'default-deny')) {
    for (const rule of (policy.spec?.egress ?? []) as { to?: Peer[]; ports?: object[] }[]) {
      assert.ok(rule.to?.length && rule.ports?.length, `${policy.metadata.name}: every egress rule names its destinations and ports`);
      for (const peer of rule.to) assert.ok(peer.podSelector || (peer.ipBlock && !/^0\.0\.0\.0\/0$|^::\/0$/.test(peer.ipBlock.cidr)), `${policy.metadata.name}: no egress to any address`);
    }
  }
  const external = resources.find((r) => r.metadata.name === 'gate-egress-idp-tsa')!.spec!.egress as { to: Peer[] }[];
  assert.equal(external.flatMap((rule) => rule.to).length, 4, 'IdP, TSA, break-glass receiver and SIEM, nothing else');
  assert.ok(!resources.some((r) => /ExternalSecret|SecretProviderClass/.test(r.kind)), 'renders without the secret-store CRDs');
});

test('replicas: no database egress, ingress and DNS pinned to named peers', { skip }, () => {
  type Sel = { matchLabels?: Record<string, string>; matchExpressions?: { key: string; operator: string; values?: string[] }[] };
  type Peer = { podSelector?: Sel; namespaceSelector?: Sel };
  type Rule = { from?: Peer[]; to?: Peer[]; ports?: { port: number }[] };
  const selects = (sel: Sel | undefined, labels: Record<string, string>): boolean =>
    Object.entries(sel?.matchLabels ?? {}).every(([k, v]) => labels[k] === v)
    && (sel?.matchExpressions ?? []).every((e) => (e.operator === 'In' ? e.values!.includes(labels[e.key] ?? '\0') : e.operator === 'NotIn' ? !e.values!.includes(labels[e.key] ?? '\0') : false));
  const labelsOf = (component: string) => ({ 'app.kubernetes.io/name': 'gate', 'app.kubernetes.io/component': component });
  for (const dir of ['deploy/k8s/overlays/sovereign-uae']) {
    const resources = render(dir);
    const policy = (name: string) => resources.find((r) => r.kind === 'NetworkPolicy' && r.metadata.name === name)!.spec as { podSelector: Sel; ingress?: Rule[]; egress?: Rule[] };
    const database = policy('gate-egress-database');
    assert.ok(!selects(database.podSelector, labelsOf('replica')), `${dir}: replicas get no PostgreSQL egress`);
    for (const component of ['server', 'migrate', 'backup', 'restore']) assert.ok(selects(database.podSelector, labelsOf(component)), `${dir}: ${component} keeps database egress`);
    const replica = policy('gate-replica');
    const ingress = replica.ingress ?? [];
    assert.ok(ingress.length && ingress.every((r) => r.from?.length), `${dir}: replica ingress names its sources`);
    assert.ok(ingress.flatMap((r) => r.from!).every((p) => p.podSelector || p.namespaceSelector), `${dir}: no empty replica ingress peer`);
    const dns = (replica.egress ?? []).find((r) => r.ports?.some((p) => p.port === 53));
    assert.ok(dns?.to?.some((p) => p.namespaceSelector && p.podSelector?.matchLabels?.['k8s-app'] === 'kube-dns'), `${dir}: replica DNS egress only to kube-dns`);
    // the scraper namespace is narrowed to its Prometheus pods (the namespace alone would reach /admin and /scim)
    const monitoring = policy('gate-ingress').ingress!.flatMap((r) => r.from ?? []).find((p) => (p.namespaceSelector?.matchLabels?.['kubernetes.io/metadata.name']) === 'monitoring');
    assert.ok(monitoring?.podSelector?.matchLabels?.['app.kubernetes.io/name'] === 'prometheus', `${dir}: monitoring limited to the Prometheus pods`);
  }
});

test('monitoring: every on-call alert is defined', { skip }, () => {
  const yaml = execFileSync('kubectl', ['kustomize', resolve(root, 'deploy/k8s/monitoring')], { encoding: 'utf8' });
  for (const alert of ['GateNoActiveNode', 'GateActiveNodeNotReady', 'GateAnchoringStale', 'GateAuditFullChainUnverified', 'GateCommitLatencyHigh', 'GateHigh5xxRate', 'GateFailover', 'GateBackupMissing',
    'GateDecisionLatencyHigh', 'GateAvailabilityBudgetBurn', 'GateReplicaStale', 'GateBreakGlassNoticeFailed']) {
    assert.match(yaml, new RegExp(`alert: ${alert}\\n`), alert);
  }
  assert.match(yaml, /kube_statefulset_status_replicas_ready\{statefulset="gate"/, 'GateNoActiveNode also covers cluster mode');
});

// Always on (files only): the manifests, scripts and image agree with the code on tables, grants and backup encryption.
test('managed offer: grants, backup tables, the encryption key and the ops image agree with the code', () => {
  const read = (path: string): string => readFileSync(resolve(root, path), 'utf8');
  const flat = (sql: string): string => sql.replace(/\s+/g, ' ').trim();
  const tables = [...SCHEMA.matchAll(/CREATE TABLE IF NOT EXISTS (gate_[a-z_]+)/g)].map((m) => m[1]);
  assert.deepEqual([...BACKUP_TABLES].sort(), [...tables].sort(), 'the backup role reads every table the schema creates');
  for (const script of ['scripts/ops/backup.sh', 'scripts/ops/restore.sh']) {
    assert.deepEqual(/^TABLES=\(([^)]*)\)/m.exec(read(script))?.[1]?.split(' '), [...BACKUP_TABLES], `${script} dumps/validates every table`);
  }
  const restoreDdl = /^SESSION_DDL='([^']*)'$/m.exec(read('scripts/ops/restore.sh'))?.[1] ?? '';
  assert.equal(flat(restoreDdl), flat(`${SESSION_TABLE} ${SESSION_POLICY}`), 'restore.sh creates gate_session exactly as SCHEMA does');
  // restore.sh creates a missing disposable table with the statements SCHEMA uses for it
  const ddl = /gate_blp_mark\) printf '%s' '([^']*)'/.exec(read('scripts/ops/restore.sh'))?.[1] ?? '';
  const statements = ddl.split(';').map((x) => flat(x)).filter(Boolean);
  assert.equal(statements.length, 4);
  for (const statement of statements) assert.ok(flat(SCHEMA).includes(statement), `SCHEMA has: ${statement}`);
  const retired = /gate_retired\) printf '%s' '([^']*)'/.exec(read('scripts/ops/restore.sh'))?.[1] ?? '';
  assert.equal(flat(retired), flat(`${RETIRED_TABLE} ${RETIRED_POLICY}`), 'restore.sh creates gate_retired exactly as SCHEMA does');
  const jobs = read('deploy/k8s/base/jobs.yaml');
  assert.match(jobs, /await client\.query\(serviceGrants\(app\)\);/, 'gate-migrate grants from the code, not a copy');
  assert.match(jobs, /await client\.query\(backupGrants\(backup\)\);/);
  assert.match(jobs, /BACKUP_FILE="\/backups\/gate-\$\(date -u \+%Y%m%dT%H%M%SZ\)\.dump\.gcm"/);
  assert.match(jobs, /-name 'gate-\*\.dump\.gcm'/, 'retention removes the encrypted archives');
  const smoke = read('scripts/managed/smoke.sh');
  const grants = /^grants="([^"]*)"$/m.exec(smoke)?.[1] ?? '';
  assert.equal(flat(grants), flat(serviceGrants('$service_role') + backupGrants('$backup_role')), 'the restore drill grants as gate-migrate does');
  assert.match(smoke, /"name":"BACKUP_ENCRYPTION_KEY","valueFrom":\{"secretKeyRef":\{"name":"gate-backup"/);
  assert.match(read('scripts/managed/new-tenant.sh'), /required=\([^)]*gate-backup[^)]*\)/);
  // new-tenant.sh refuses to apply a render that still holds a placeholder, the documentation IP ranges included
  const placeholders = /^placeholders='([^']*)'$/m.exec(read('scripts/managed/new-tenant.sh'))?.[1];
  assert.ok(placeholders, 'new-tenant.sh names its placeholder pattern');
  const holds = (line: string): boolean => spawnSync('grep', ['-qE', placeholders], { input: line }).status === 0;
  for (const line of ['host: tenant.gate.example.invalid', `image: gate@sha256:${'0'.repeat(64)}`, '- TRUSTED_PROXIES=192.0.2.64/26',
    '- ipBlock: {cidr: 198.51.100.0/28}', '- ipBlock: {cidr: 203.0.113.16/28}', 'cidr: 192.0.2.0/28']) assert.ok(holds(line), line);
  for (const line of ['- TRUSTED_PROXIES=10.0.0.0/8', 'cidr: 192.0.20.0/24', 'cidr: 10.192.0.2/32', 'cidr: 203.0.11.0/24']) assert.ok(!holds(line), line);
  // and refuses database URLs that carry their own TLS settings, which Qadamar and the ops scripts would refuse at start
  const urlTls = /^url_tls='([^']*)'$/m.exec(read('scripts/managed/new-tenant.sh'))?.[1];
  assert.ok(urlTls, 'new-tenant.sh names its URL TLS-parameter pattern');
  const refused = (url: string): boolean => spawnSync('bash', ['-c', '[[ $1 =~ $2 ]]', '_', url, urlTls]).status === 0;
  for (const url of ['postgresql://db.internal/gate?sslmode=verify-full', 'postgresql://db.internal/gate?application_name=x&sslrootcert=/etc/gate/db/ca.pem', 'postgres://h/d?ssl=true']) assert.ok(refused(url), url);
  for (const url of ['postgresql://db.internal/gate', 'postgresql://db.internal/gate?application_name=sslmode']) assert.ok(!refused(url), url);
  assert.match(read('scripts/managed/new-tenant.sh'), /required\+=\(gate-postgres-tls /, 'the sovereign overlay requires the database CA Secret');
  const dockerfile = read('Dockerfile');
  const ops = /^FROM \$\{OPS_BASE\} AS ops\n([\s\S]*?)\n\n/m.exec(dockerfile)?.[1] ?? '';
  // the published ops image is slim: node plus bash and the PostgreSQL client, no server, LLVM or gosu
  assert.match(dockerfile, /^ARG OPS_BASE=ops-base-slim$/m, 'the published ops image builds on the slim base');
  const slim = /^FROM \$\{NODE_IMAGE\} AS ops-base-slim\n([\s\S]*?)\nFROM /m.exec(dockerfile)?.[1] ?? '';
  assert.match(slim, /apk add --no-cache bash postgresql(\d+)-client \\/, 'the slim base adds only bash and the PostgreSQL client');
  assert.equal(/postgresql(\d+)-client/.exec(slim)?.[1], /^ARG POSTGRES_IMAGE=postgres:(\d+)-/m.exec(dockerfile)?.[1], 'pg_dump matches the server major version');
  assert.match(read('scripts/managed/build-local-image.sh'), /OPS_BASE=runtime-base-postgres --target ops/, 'the offline local build keeps the PostgreSQL base');
  for (const file of readdirSync(resolve(root, 'scripts/ops'))) assert.match(ops, new RegExp(`scripts/ops/${file.replace('.', '\\.')}\\b`), `the ops image carries scripts/ops/${file}`);
  assert.match(ops, /apk upgrade --no-cache/, 'the ops image brings its alpine packages to their fixed versions');
  assert.match(ops, /rm -f \/usr\/local\/bin\/gosu/, 'the ops image drops the base image gosu binary');
  // backup.sh and restore.sh look for their node helpers beside themselves: each one must be in /opt/gate
  const helpers = new Set([...(read('scripts/ops/backup.sh') + read('scripts/ops/restore.sh')).matchAll(/&& pwd\)\/([a-z-]+\.ts)"/g)].map((match) => match[1]));
  assert.deepEqual([...helpers].sort(), ['archive-crypt.ts', 'database-tls.ts', 'migrate-records.ts']);
  const placed = ops.split('\n').filter((line) => line.endsWith(' /opt/gate/')).join('\n');
  for (const helper of helpers) assert.ok(placed.includes(`/${helper} `), `the ops image places ${helper} beside the backup scripts`);
});
