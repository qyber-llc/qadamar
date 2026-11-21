import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { decodePng, parseColor, required, textContrast } from './contrast.ts';

// Playwright is not a dependency: a local playwright-core is used when present, typed here by what the tests call.
export interface Locator { screenshot(): Promise<Buffer>; press(key: string): Promise<void>; focus(): Promise<void>; click(): Promise<void>; fill(v: string): Promise<void>; inputValue(): Promise<string>; textContent(): Promise<string | null>; waitFor(o?: { state?: string; timeout?: number }): Promise<void>; count(): Promise<number>; first(): Locator; getAttribute(n: string): Promise<string | null> }
export interface Page {
  goto(url: string): Promise<unknown>; reload(): Promise<unknown>; close(): Promise<void>;
  evaluate<R, A = undefined>(fn: (arg: A) => R | Promise<R>, arg?: A): Promise<R>;
  waitForFunction<A>(fn: (arg: A) => unknown, arg?: A, options?: { timeout?: number }): Promise<unknown>;
  waitForTimeout(ms: number): Promise<void>;
  locator(selector: string): Locator;
  keyboard: { press(key: string): Promise<void>; type(text: string): Promise<void> };
  screenshot(o?: { fullPage?: boolean }): Promise<Buffer>;
  setViewportSize(s: { width: number; height: number }): Promise<void>;
  viewportSize(): { width: number; height: number } | null;
  on(event: 'console', fn: (m: { type(): string; text(): string; location(): { url: string } }) => void): void;
  on(event: 'pageerror', fn: (e: Error) => void): void;
}
export interface Context {
  newPage(): Promise<Page>; close(): Promise<void>;
  request: { post(url: string, o: { data: unknown }): Promise<{ status(): number }> };
  storageState(): Promise<unknown>;
  addInitScript<T>(script: (arg: T) => void, arg: T): Promise<void>;
  newCDPSession(page: Page): Promise<{ send(method: string, params?: object): Promise<any> }>;
}
export interface Browser { newContext(o: object): Promise<Context>; close(): Promise<void> }

/** playwright-core copies to try, in order: PLAYWRIGHT_CORE_PATH (or the older PLAYWRIGHT_CORE) alone when set; else one
 *  resolvable from here, then this user's npx cache, newest first (`npx playwright install chromium` leaves them there). */
export function playwrightCorePaths(env: NodeJS.ProcessEnv = process.env, npxCache = join(homedir(), '.npm/_npx')): string[] {
  const explicit = env.PLAYWRIGHT_CORE_PATH ?? env.PLAYWRIGHT_CORE;
  if (explicit) return [explicit];
  const found: string[] = [];
  try { found.push(dirname(createRequire(import.meta.url).resolve('playwright-core/package.json'))); } catch { /* not installed here */ }
  const cached = existsSync(npxCache) ? readdirSync(npxCache).map((d) => join(npxCache, d, 'node_modules/playwright-core')).filter((p) => existsSync(p)) : [];
  return [...found, ...cached.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)];
}

/** The browser, or why the browser tests skip (no playwright-core, or no Chromium for any copy found). With
 *  E2E_REQUIRED=1 a reason to skip is an error instead, so a job that must run the browser tests cannot pass by skipping. */
export async function launch(env: NodeJS.ProcessEnv = process.env, paths = playwrightCorePaths(env)): Promise<Browser | string> {
  const reasons: string[] = [];
  for (const path of paths) {
    const result = await tryLaunch(path);
    if (typeof result !== 'string') return result;
    reasons.push(result);
  }
  const reason = reasons.join('; ') || 'playwright-core not found: set PLAYWRIGHT_CORE_PATH to run the browser tests';
  if (/^(1|true|yes|on)$/i.test(env.E2E_REQUIRED ?? '')) throw new Error(`E2E_REQUIRED is set and the browser tests cannot run: ${reason}`);
  return reason;
}
async function tryLaunch(path: string): Promise<Browser | string> {
  if (!existsSync(path)) return `playwright-core not found at ${path}: set PLAYWRIGHT_CORE_PATH to run the browser tests`;
  try {
    const { chromium } = createRequire(import.meta.url)(path) as { chromium: { launch(): Promise<Browser> } };
    return await chromium.launch();
  } catch (err) {
    return `Chromium could not start through ${path}: ${err instanceof Error ? err.message.split('\n')[0] : String(err)}`;
  }
}

const repo = resolve(import.meta.dirname, '../../..');
export const SEAL = 'e2e0'.repeat(16);

/** The real PDP server, file mode, demo world, serving the built console. The demo passwords are read once. */
export async function startServer(): Promise<{ url: string; passwords: Record<string, string>; close: () => Promise<void> }> {
  const staticDir = resolve(repo, 'apps/admin/dist');
  if (!existsSync(join(staticDir, 'index.html'))) throw new Error('apps/admin/dist is missing: run pnpm --filter @product/admin build');
  const dataDir = mkdtempSync(join(tmpdir(), 'qadamar-e2e-'));
  const serverPath = resolve(repo, 'packages/pdp-http/src/server.ts');
  const { createServer } = await import(serverPath) as { createServer(o: object): { listen(): Promise<void>; close(): Promise<void>; url: string } };
  const server = createServer({
    port: 0, dataDir, worldDir: resolve(repo, 'examples/toy-domain'), staticDir, clock: 'fixed:2026-11-08T10:00:00Z',
    signingKeySeal: SEAL, rateLimit: 100_000,
  });
  await server.listen();
  const { passwords } = JSON.parse(readFileSync(join(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  return { url: server.url, passwords, close: async () => { await server.close(); rmSync(dataDir, { recursive: true, force: true }); } };
}

/** Console errors and uncaught exceptions; the 401 of the session probe on the sign-in page is the expected answer. */
export function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    if (/status of 401/.test(m.text()) && /\/admin\/v1\/session$/.test(m.location().url)) return;
    errors.push(`${m.text()} (${m.location().url})`);
  });
  page.on('pageerror', (e) => errors.push(`uncaught: ${e.message}`));
  return errors;
}

/** Waits until the screen's heading is there and no loading card is left. */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(() => {
    const main = document.querySelector('main');
    return main && main.querySelector('h1') && !main.querySelector('.card[role="status"][aria-live="polite"]') && document.fonts.status === 'loaded';
  }, undefined, { timeout: 15_000 });
  // then until the page stops changing for 300 ms (late data, a table filling in)
  await page.evaluate(() => new Promise<void>((done) => {
    let timer = window.setTimeout(finish, 300);
    const cap = window.setTimeout(finish, 3000); // a ticking countdown never goes quiet
    const mo = new MutationObserver(() => { window.clearTimeout(timer); timer = window.setTimeout(finish, 300); });
    function finish() { window.clearTimeout(timer); window.clearTimeout(cap); mo.disconnect(); requestAnimationFrame(() => requestAnimationFrame(() => done())); }
    mo.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
  }));
}

/** Interactive elements without an accessible name, from Chromium's own accessibility tree. */
export async function unnamedControls(context: Context, page: Page): Promise<{ checked: number; unnamed: string[] }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('DOM.getDocument', { depth: -1 });
  const { nodes } = await cdp.send('Accessibility.getFullAXTree') as { nodes: { ignored: boolean; role?: { value: string }; name?: { value: string }; backendDOMNodeId?: number }[] };
  const roles = new Set(['button', 'link', 'textbox', 'searchbox', 'combobox', 'checkbox', 'switch', 'radio', 'spinbutton', 'slider', 'tab', 'menuitem', 'listbox']);
  const out: string[] = [];
  let checked = 0;
  for (const n of nodes) {
    if (n.ignored || !n.role || !roles.has(n.role.value)) continue;
    checked++;
    if ((n.name?.value ?? '').trim()) continue;
    const html = n.backendDOMNodeId ? (await cdp.send('DOM.getOuterHTML', { backendNodeId: n.backendDOMNodeId })).outerHTML as string : '?';
    out.push(`${n.role.value}: ${html.slice(0, 160)}`);
  }
  return { checked, unnamed: out };
}

interface TextItem { text: string; color: string; opacity: number; size: number; weight: number; boxes: { x: number; y: number; w: number; h: number }[]; path: string }

/** Every visible text node with its colour, size and line boxes (clipped by scrolling ancestors), measured with the
 *  viewport as tall as the page so nothing needs scrolling; then the same view with the glyphs made transparent. */
export async function contrastFailures(page: Page): Promise<{ checked: number; failures: string[] }> {
  const viewport = page.viewportSize() ?? { width: 1280, height: 900 };
  const height = await page.evaluate(() => Math.max(document.documentElement.scrollHeight, document.body.scrollHeight));
  await page.setViewportSize({ width: viewport.width, height: Math.min(Math.max(height, viewport.height), 4000) });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  const items = await page.evaluate(() => {
    const out: TextItem[] = [];
    // any CSS colour syntax (oklch, color-mix…) to 8-bit sRGB with alpha, through a 1×1 canvas
    const ink = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!;
    const toRgba = (css: string) => {
      ink.clearRect(0, 0, 1, 1);
      ink.fillStyle = css;
      ink.fillRect(0, 0, 1, 1);
      const [r, g, b, a] = ink.getImageData(0, 0, 1, 1).data;
      return `rgba(${r}, ${g}, ${b}, ${(a! / 255).toFixed(3)})`;
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const path = (el: Element) => {
      const parts: string[] = [];
      for (let e: Element | null = el; e && parts.length < 4; e = e.parentElement) parts.unshift(e.tagName.toLowerCase() + (e.id ? `#${e.id}` : e.classList.length ? `.${[...e.classList].slice(0, 2).join('.')}` : ''));
      return parts.join(' > ');
    };
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent?.trim();
      const el = node.parentElement;
      // WCAG 1.4.3 exempts logotypes (the product name drawn into the splash image) and inactive controls
      if (!text || !el || el.closest('script, style, noscript, option, :disabled, [data-logotype]')) continue;
      if (!el.checkVisibility({ opacityProperty: true, visibilityProperty: true })) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      let boxes = [...range.getClientRects()].map((r) => ({ x: r.left, y: r.top, w: r.width, h: r.height }));
      for (let a = el; a; a = a.parentElement as HTMLElement) {
        const cs = getComputedStyle(a);
        if (cs.overflowX === 'visible' && cs.overflowY === 'visible' && cs.clip === 'auto') continue;
        // the padding box: a scroll container clips inside its border and scrollbar
        const r = a.getBoundingClientRect();
        const c = { left: r.left + a.clientLeft, top: r.top + a.clientTop, right: r.left + a.clientLeft + a.clientWidth, bottom: r.top + a.clientTop + a.clientHeight };
        if (a === document.documentElement || a === document.body) continue;
        boxes = boxes.map((b) => {
          const x = Math.max(b.x, c.left), y = Math.max(b.y, c.top);
          return { x, y, w: Math.min(b.x + b.w, c.right) - x, h: Math.min(b.y + b.h, c.bottom) - y };
        });
      }
      boxes = boxes.filter((b) => b.w > 2 && b.h > 2);
      if (boxes.length === 0) continue;
      const cs = getComputedStyle(el);
      let opacity = 1;
      for (let a: Element | null = el; a; a = a.parentElement) opacity *= Number(getComputedStyle(a).opacity);
      const svgFill = el instanceof SVGElement ? `color-mix(in srgb, ${cs.fill} ${Number(cs.fillOpacity) * 100}%, transparent)` : null;
      out.push({ text: text.slice(0, 50), color: toRgba(svgFill ?? cs.color), opacity, size: parseFloat(cs.fontSize), weight: Number(cs.fontWeight), boxes, path: path(el) });
    }
    return out;
  });
  // a constructed style sheet: the page's CSP (default-src 'self') refuses an injected <style>, not this
  await page.evaluate(() => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync('*, *::before, *::after, *::placeholder { -webkit-text-fill-color: transparent !important; text-shadow: none !important; text-decoration-color: transparent !important; caret-color: transparent !important; }');
    (window as unknown as { e2eHide: CSSStyleSheet }).e2eHide = sheet;
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  });
  await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  const image = decodePng(await page.screenshot());
  await page.evaluate(() => { document.adoptedStyleSheets = document.adoptedStyleSheets.filter((x) => x !== (window as unknown as { e2eHide: CSSStyleSheet }).e2eHide); });
  await page.setViewportSize(viewport);
  const failures: string[] = [];
  for (const item of items) {
    const [r, g, b, a] = parseColor(item.color);
    const { ratio, background } = textContrast(image, [r, g, b, a * item.opacity], item.boxes);
    const need = required(item.size, item.weight);
    if (ratio < need) failures.push(`${ratio.toFixed(2)} < ${need}: "${item.text}" ${item.color} on rgb(${background.map(Math.round).join(',')}) ${item.size}px/${item.weight} at ${item.path}`);
  }
  return { checked: items.length, failures };
}

/** Tabs through the page from the top: every focusable, visible control is reached once, in document order, with a
 *  visible focus indicator (outline, ring or border that differs from its resting style), and not hidden by another
 *  element. Returns the problems found. */
export async function keyboardWalk(page: Page, maxSteps = 400): Promise<{ problems: string[]; order: string[] }> {
  const expected = await page.evaluate(() => {
    const sel = 'a[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]';
    const all = [...document.querySelectorAll<HTMLElement>(sel)];
    const style = (el: Element) => {
      const cs = getComputedStyle(el);
      return [cs.outlineStyle, cs.outlineWidth, cs.outlineColor, cs.boxShadow, cs.borderTopColor, cs.borderBottomColor].join('|');
    };
    const out: { id: number; label: string; tabbable: boolean }[] = [];
    all.forEach((el, id) => {
      el.dataset.e2eId = String(id);
      el.dataset.e2eRest = [el, el.parentElement, el.parentElement?.parentElement].map((e) => (e ? style(e) : '')).join('#');
      const disabled = (el as HTMLButtonElement).disabled === true;
      const tabbable = el.tabIndex >= 0 && !disabled && !el.closest('[inert]') && el.checkVisibility({ visibilityProperty: true }) && el.getClientRects().length > 0;
      out.push({ id, label: `${el.tagName.toLowerCase()} "${(el.getAttribute('aria-label') ?? el.textContent ?? '').trim().slice(0, 40)}"${el.id ? '#' + el.id : ''}`, tabbable });
    });
    // start from the top of the document whatever had focus: a non-tabbable marker first in <body>
    const start = document.createElement('span');
    start.id = 'e2e-start';
    start.tabIndex = -1;
    document.body.prepend(start);
    start.focus();
    window.scrollTo(0, 0);
    return out;
  });
  const problems: string[] = [];
  const positive = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('[tabindex]')].filter((e) => e.tabIndex > 0).length);
  if (positive > 0) problems.push(`${positive} element(s) with a positive tabindex`);
  const seen: number[] = [];
  for (let step = 0; step < maxSteps; step++) {
    await page.keyboard.press('Tab');
    const at = await page.evaluate(async () => {
      // the focus style may arrive through a transition: read it once the running ones end
      const running = document.getAnimations().filter((a) => a.playState === 'running' && a.effect && Number(a.effect.getComputedTiming().endTime) < 2000);
      await Promise.race([Promise.all(running.map((a) => a.finished.catch(() => undefined))), new Promise((r) => setTimeout(r, 2000))]);
      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
      const el = document.activeElement as HTMLElement | null;
      if (!el || el === document.body) return null;
      if (!el.dataset.e2eId) return { id: -1, indicator: true, covered: '' };
      const style = (e: Element) => {
        const cs = getComputedStyle(e);
        return [cs.outlineStyle, cs.outlineWidth, cs.outlineColor, cs.boxShadow, cs.borderTopColor, cs.borderBottomColor].join('|');
      };
      const now = [el, el.parentElement, el.parentElement?.parentElement].map((e) => (e ? style(e) : ''));
      const rest = (el.dataset.e2eRest ?? '').split('#');
      const cs = getComputedStyle(el);
      const outline = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1 && !/rgba\([^)]*,\s*0\)|transparent/.test(cs.outlineColor);
      const indicator = outline || now.some((s, i) => s !== rest[i]);
      const r = el.getBoundingClientRect();
      const cx = Math.min(Math.max(r.left + r.width / 2, 0), innerWidth - 1), cy = Math.min(Math.max(r.top + r.height / 2, 0), innerHeight - 1);
      const top = document.elementFromPoint(cx, cy);
      const covered = r.width > 0 && top !== null && top !== el && !el.contains(top) && !top.contains(el);
      return { id: Number(el.dataset.e2eId), indicator, covered: covered ? (top?.outerHTML.slice(0, 80) ?? '') : '' };
    });
    if (!at) { if (seen.length > 0) break; continue; }
    if (at.id < 0) continue; // added after the page settled (a live region, a lazy row): not in the expected list
    if (seen.length > 0 && at.id === seen[0]) break;
    const label = expected[at.id]?.label ?? String(at.id);
    if (!at.indicator) problems.push(`no visible focus indicator on ${label}`);
    if (at.covered) problems.push(`${label} is hidden under ${at.covered} when focused`);
    if (seen.includes(at.id)) problems.push(`${label} reached twice`);
    else if (seen.length > 0 && at.id < seen[seen.length - 1]!) problems.push(`${label} comes after ${expected[seen[seen.length - 1]!]?.label} but precedes it in the document`);
    seen.push(at.id);
  }
  await page.evaluate(() => document.getElementById('e2e-start')?.remove());
  for (const e of expected) if (e.tabbable && !seen.includes(e.id)) problems.push(`never reached: ${e.label}`);
  return { problems, order: seen.map((id) => expected[id]?.label ?? String(id)) };
}
