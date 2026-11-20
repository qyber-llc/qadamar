// Example backend behind the enforcing gateway: plain node:http, no framework. Every request must carry the gateway's
// decision assertion; the handler runs only for the request the PDP decided, and reads who, what and which item from
// the verified claims, never from caller-controlled headers.
//   GATE_JWKS_URL=https://pdp.internal/.well-known/jwks.json GATE_AUDIENCE=http://10.0.0.5:8080 PORT=8080 \
//     node packages/sdk/src/example-backend.ts
import { createServer, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';
import { AssertionVerifier, withGateAssertion } from './assertion.ts';

export function exampleBackend(verifier: AssertionVerifier): Server {
  return createServer(withGateAssertion(verifier, (req, res, { claims, body }) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ subject: claims.sub, action: claims.act, resource: claims.res, decisionId: claims.did, method: req.method, bytes: body.length }));
  }));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { GATE_JWKS_URL: jwksUrl = '', GATE_AUDIENCE: audience = '', PORT: port = '8080' } = process.env;
  exampleBackend(new AssertionVerifier({ jwksUrl, audience })).listen(Number(port), () => console.info(`backend on :${port}, audience ${audience}`));
}
