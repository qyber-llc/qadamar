// The Explain drawer shows a decision only for the inputs it was evaluated with (console review finding 3).
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { explainInputs, sameExplainInputs } = await vite.ssrLoadModule('/src/components/ExplainDrawer.tsx');

test('explain inputs are normalised: level parsed, maker trimmed, prior actions split', () => {
  assert.deepEqual(explainInputs('trusted', '', '  ', ' , '), { network: 'trusted', priorActions: [] });
  assert.deepEqual(explainInputs('untrusted', '2', ' grace ', 'create, approve ,'),
    { network: 'untrusted', sessionLevel: 2, makerId: 'grace', priorActions: ['create', 'approve'] });
  assert.deepEqual(explainInputs('trusted', '7', '', ''), { network: 'trusted', priorActions: [] }, 'an unknown level is not sent');
});

test('a change of session level, maker or prior actions makes the shown decision stale; whitespace does not', () => {
  const evaluated = explainInputs('trusted', '', '', '');
  assert.equal(sameExplainInputs(evaluated, explainInputs('trusted', '', ' ', ' ')), true);
  assert.equal(sameExplainInputs(evaluated, explainInputs('trusted', '0', '', '')), false);
  assert.equal(sameExplainInputs(evaluated, explainInputs('trusted', '', 'grace', '')), false);
  assert.equal(sameExplainInputs(evaluated, explainInputs('trusted', '', '', 'create')), false);
  assert.equal(sameExplainInputs(evaluated, explainInputs('untrusted', '', '', '')), false);
});
