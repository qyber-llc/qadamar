// The sovereign-uae overlay says "TLS everywhere": the decision replicas serve TLS themselves, as the Qadamar pods do.
// Opt-in like k8s.test.ts: GATE_K8S_TEST=1, kubectl on the PATH (kustomize render only, nothing is sent to a cluster).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const skip = process.env.GATE_K8S_TEST === '1' ? false : 'set GATE_K8S_TEST=1 to check the Kubernetes manifests (needs kubectl)';
const root = resolve(import.meta.dirname, '../../..');

test('sovereign-uae overlay: the replicas serve TLS from the pod TLS Secret and are probed over https', { skip }, () => {
  const yaml = execFileSync('kubectl', ['kustomize', resolve(root, 'deploy/k8s/overlays/sovereign-uae')], { encoding: 'utf8' });
  const doc = yaml.split(/^---$/m).find((d) => /^kind: StatefulSet$/m.test(d) && /^  name: gate-replica$/m.test(d));
  assert.ok(doc, 'gate-replica StatefulSet rendered');
  const gate = doc.slice(doc.indexOf('      containers:'));
  assert.match(gate, /name: TLS_CERT_FILE\n\s+value: \/etc\/gate\/tls\/tls\.crt/);
  assert.match(gate, /name: TLS_KEY_FILE\n\s+value: \/etc\/gate\/tls\/tls\.key/);
  assert.match(gate, /mountPath: \/etc\/gate\/tls\n\s+name: tls\n\s+readOnly: true/);
  assert.match(doc, /- name: tls\n\s+secret:\n\s+defaultMode: 288\n\s+secretName: gate-pod-tls/);
  for (const probe of ['readinessProbe', 'livenessProbe', 'startupProbe']) {
    assert.match(gate, new RegExp(`${probe}:\\n(?:\\s+\\w+: .*\\n)*?\\s+httpGet:\\n(?:\\s+\\w+: .*\\n)*?\\s+scheme: HTTPS`), `${probe} over https`);
  }
  assert.match(doc, /prometheus\.io\/scheme: https/);
});
