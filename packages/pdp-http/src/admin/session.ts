import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Saml } from '../saml.ts';
import type { Auth } from '../auth.ts';
import { HttpError, json, secureFlag } from '../http.ts';

export async function session(auth: Auth, req: IncomingMessage, res: ServerResponse, b: Record<string, unknown>, ip: string, validated?: ReturnType<Auth['session']>, security: { publicOrigin?: string; passwordLogin?: boolean; saml?: Saml } = {}, commit: () => Promise<void> = async () => undefined): Promise<void> {
  const secure = secureFlag(req, security.publicOrigin);
  if (req.method === 'POST') {
    if (security.passwordLogin === false) throw new HttpError(403, 'password_login_disabled', 'Sign in through your organisation (SSO)');
    const result = await auth.login(b.username, b.password, ip, b.code);
    await commit();
    res.setHeader('Set-Cookie', `sid=${result.sid}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=28800${secure}`);
    json(res, { user: result.user, csrfToken: result.csrfToken }); return;
  }
  const value = validated ?? auth.session(req, req.method !== 'GET');

  if (req.method === 'DELETE') {
    const target = auth.samlTarget(req);
    const logoutUrl = target && security.saml?.logoutEnabled ? await security.saml.startLogout(target) : undefined;
    if (target) await auth.endOidcSessions(target, 'saml');
    auth.logout(req, value.user.id);
    await commit();
    res.setHeader('Set-Cookie', `sid=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0${secure}`);
    if (logoutUrl) json(res, { logoutUrl }); else json(res, undefined, 204); return;
  }
  json(res, value);
}
