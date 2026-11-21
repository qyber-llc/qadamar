import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { decodePng } from './contrast.ts';
import { contrastFailures, keyboardWalk, launch, settle, startServer, unnamedControls, watchErrors, type Browser, type Context, type Page } from './harness.ts';

/** Real-browser checks of the console (docs/ACCESSIBILITY.md): the real PDP server in file mode with the demo world,
 *  serving the built console, in English (light colour scheme) and French (dark colour scheme). */
const browser = await launch();
const SKIP = typeof browser === 'string' ? browser : false;
if (SKIP) console.log(`browser tests skipped: ${SKIP}`);

const ROUTES = ['overview', 'model', 'policies', 'matrix', 'simulator', 'approvals', 'break-glass', 'reviews', 'credentials', 'audit', 'compliance', 'two-step'] as const;
const LANGS = [{ lang: 'en', locale: 'en-GB', colorScheme: 'light' }, { lang: 'fr', locale: 'fr-FR', colorScheme: 'dark' }, { lang: 'ar', locale: 'ar-AE', colorScheme: 'dark' }] as const;
const VIEWPORT = { width: 1280, height: 900 };

let server: Awaited<ReturnType<typeof startServer>>;
let signedIn: Record<string, unknown> = {};
const b = browser as Browser;

before(async () => {
  if (SKIP) return;
  server = await startServer();
  // one sign-in per demo user (the login throttle counts them); every context reuses the cookie
  for (const user of ['lina', 'sam']) {
    const ctx = await b.newContext({ baseURL: server.url });
    const res = await ctx.request.post('/admin/v1/session', { data: { username: user, password: server.passwords[user] } });
    assert.equal(res.status(), 200, `${user} signs in`);
    signedIn[user] = await ctx.storageState();
    await ctx.close();
  }
});
after(async () => {
  if (SKIP) return;
  await b.close();
  await server.close();
});

async function open(options: { user?: string; locale?: string; colorScheme?: string; reducedMotion?: string; forcedColors?: string } = {}): Promise<{ ctx: Context; page: Page; errors: string[] }> {
  const ctx = await b.newContext({
    baseURL: server.url, viewport: VIEWPORT, locale: options.locale ?? 'en-GB', colorScheme: options.colorScheme ?? 'light',
    forcedColors: options.forcedColors ?? 'none', reducedMotion: options.reducedMotion ?? 'reduce', ...(options.user ? { storageState: signedIn[options.user] } : {}),
  });
  // a fresh browser opens in English (i18n.test.ts); the locale stands for a language this person chose earlier
  const lang = (options.locale ?? 'en-GB').slice(0, 2);
  await ctx.addInitScript((l) => { if (!window.localStorage.getItem('qadamar-lang')) window.localStorage.setItem('qadamar-lang', l); }, lang);
  const page = await ctx.newPage();
  return { ctx, page, errors: watchErrors(page) };
}

const report = (title: string, problems: readonly string[]) => assert.deepEqual(problems, [], `${title}:\n  ${problems.join('\n  ')}`);

/** Every check of one screen, each also proving it looked at something: names, contrast, keyboard. */
async function audit(ctx: Context, page: Page, minimum: { controls: number; texts: number; stops: number }): Promise<string[]> {
  const names = await unnamedControls(ctx, page);
  const contrast = await contrastFailures(page);
  const walk = await keyboardWalk(page);
  return [
    ...names.unnamed.map((e) => `no accessible name: ${e}`),
    ...contrast.failures.map((e) => `contrast ${e}`),
    ...walk.problems.map((e) => `keyboard: ${e}`),
    ...(names.checked < minimum.controls ? [`only ${names.checked} controls in the accessibility tree`] : []),
    ...(contrast.checked < minimum.texts ? [`only ${contrast.checked} text nodes measured`] : []),
    ...(walk.order.length < minimum.stops ? [`only ${walk.order.length} tab stops`] : []),
  ];
}
const SHELL = { controls: 20, texts: 30, stops: 20 };

for (const { lang, locale, colorScheme } of LANGS) {
  test(`sign-in page (${lang}): language, names, contrast, keyboard order, sign-in with the keyboard alone`, { skip: SKIP }, async () => {
    const { ctx, page, errors } = await open({ locale, colorScheme });
    await page.goto('/');
    await settle(page);
    assert.equal(await page.evaluate(() => document.documentElement.lang), lang);
    report('sign-in page', await audit(ctx, page, { controls: 4, texts: 8, stops: 4 }));
    const walk = await keyboardWalk(page);
    assert.deepEqual(walk.order.slice(0, 4).map((l) => /#(signin-\w+)/.exec(l)?.[1] ?? l.split(' ')[0]), ['signin-username', 'signin-password', 'signin-code', 'button']);
    await page.locator('#signin-username').focus();
    await page.keyboard.type('omar');
    await page.keyboard.press('Tab');
    await page.keyboard.type(lang === 'en' ? server.passwords.omar! : 'not the password');
    await page.keyboard.press('Enter');
    if (lang === 'en') {
      await settle(page);
      assert.equal(await page.locator('section[aria-labelledby="title-overview"]').count(), 1, 'the console opens on the overview');
    } else {
      await page.locator('#signin-error').waitFor();
      assert.equal(await page.locator('#signin-username').getAttribute('aria-invalid'), 'true');
    }
    report('console errors', errors.filter((e) => !(lang !== 'en' && /status of 401/.test(e))));
    await ctx.close();
  });

  test(`every main screen (${lang}, ${colorScheme}): no console error, html lang, accessible names, contrast, keyboard`, { skip: SKIP }, async (t) => {
    const { ctx, page, errors } = await open({ user: 'lina', locale, colorScheme });
    await page.goto('/#/overview');
    for (const route of ROUTES) {
      await t.test(route, async () => {
        await page.goto(`/#/${route}`);
        await settle(page);
        assert.equal(await page.evaluate(() => document.documentElement.lang), lang);
        const problems = [
          ...errors.splice(0).map((e) => `console: ${e}`),
          ...(await audit(ctx, page, SHELL)),
        ];
        report(`${lang} ${route}`, problems);
      });
    }
    await ctx.close();
  });
}

test('the language switch sets html lang and the text, and is reachable by keyboard', { skip: SKIP }, async () => {
  const { ctx, page, errors } = await open({ user: 'lina' });
  await page.goto('/#/overview');
  await settle(page);
  await page.locator('button[lang="fr"]').focus();
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.documentElement.lang === 'fr');
  assert.match(await page.locator('a[aria-current="page"]').first().textContent() ?? '', /Vue d’ensemble/);
  assert.equal(await page.locator('button[lang="fr"]').getAttribute('aria-pressed'), 'true');
  await page.locator('button[lang="en"]').focus();
  await page.keyboard.press(' ');
  await page.waitForFunction(() => document.documentElement.lang === 'en');
  report('console errors', errors);
  await ctx.close();
});

test('dialogs trap focus and give it back: confirmation, explanation drawer, invariants popover', { skip: SKIP }, async () => {
  const { ctx, page, errors } = await open({ user: 'lina' });
  const inDialog = () => page.evaluate(() => Boolean(document.activeElement?.closest('[role="dialog"]')));
  const trapped = async () => {
    for (const key of ['Tab', 'Tab', 'Tab', 'Tab', 'Tab', 'Shift+Tab', 'Shift+Tab', 'Shift+Tab', 'Shift+Tab', 'Shift+Tab', 'Shift+Tab']) {
      await page.keyboard.press(key);
      assert.ok(await inDialog(), `focus stays in the dialog after ${key}`);
    }
    assert.equal(await page.evaluate(() => document.querySelector('#app-shell-root > aside')?.closest('[inert]') !== null || document.querySelector('aside')?.hasAttribute('inert')), true, 'the page behind is inert');
  };
  const focusedText = () => page.evaluate(() => (document.activeElement?.textContent ?? '').trim());

  await page.goto('/#/credentials');
  await settle(page);
  const rotate = page.locator('#keys-title ~ button, [aria-labelledby="keys-title"] button.btn-danger').first();
  await rotate.focus();
  const label = await focusedText();
  await page.keyboard.press('Enter');
  await page.locator('[role="dialog"][aria-modal="true"]').waitFor();
  assert.ok(await inDialog(), 'focus moves into the confirmation');
  await trapped();
  await page.keyboard.press('Escape');
  await page.locator('[role="dialog"]').waitFor({ state: 'detached' });
  assert.equal(await focusedText(), label, 'Escape returns focus to the button that opened it');

  await page.goto('/#/simulator');
  await settle(page);
  const explain = page.locator('main table button.btn-sm').first();
  await explain.waitFor();
  await explain.focus();
  const explainLabel = await page.evaluate(() => document.activeElement?.getAttribute('aria-label'));
  await page.keyboard.press('Enter');
  await page.locator('[role="dialog"][aria-modal="true"]').waitFor();
  await page.waitForTimeout(300);
  assert.ok(await inDialog(), 'focus moves into the drawer');
  await trapped();
  await page.keyboard.press('Escape');
  await page.locator('[role="dialog"]').waitFor({ state: 'detached' });
  assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), explainLabel, 'focus returns to the Explain button');

  const invariants = page.locator('header button[aria-haspopup="dialog"]');
  await invariants.focus();
  await page.keyboard.press('Enter');
  await page.locator('header [role="dialog"]').waitFor();
  await page.keyboard.press('Escape');
  assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-haspopup')), 'dialog', 'Escape returns focus to Invariants');
  report('console errors', errors);
  await ctx.close();
});

/** Pixels of two screenshots a moment apart: unchanged when nothing moves. */
async function moving(page: Page, gapMs: number): Promise<boolean> {
  const a = decodePng(await page.screenshot()).rgba;
  await page.waitForTimeout(gapMs);
  const c = decodePng(await page.screenshot()).rgba;
  let differ = 0;
  for (let i = 0; i < a.length; i += 4) if (Math.abs(a[i]! - c[i]!) + Math.abs(a[i + 1]! - c[i + 1]!) + Math.abs(a[i + 2]! - c[i + 2]!) > 24) differ++;
  return differ > 50;
}

test('reduced motion: the system setting and the console switch stop the intro and every movement', { skip: SKIP }, async () => {
  const still = await open({ user: 'lina', reducedMotion: 'reduce' });
  await still.page.goto('/#/overview');
  await settle(still.page);
  assert.equal(await still.page.evaluate(() => document.querySelector('.v24-boot')?.checkVisibility() ?? false), false, 'no intro');
  const long = () => still.page.evaluate(() => document.getAnimations().filter((a) => a.playState === 'running' && Number(a.effect?.getComputedTiming().endTime ?? 0) > 50).length);
  assert.equal(await long(), 0, 'no running animation');
  assert.equal(await moving(still.page, 800), false, 'nothing on screen moves');
  await still.ctx.close();
  const signIn = await open({ reducedMotion: 'reduce' });
  await signIn.page.goto('/');
  await settle(signIn.page);
  assert.equal(await signIn.page.evaluate(() => [...document.querySelectorAll('video')].some((v) => !v.paused)), false, 'the sign-in video does not play');
  await signIn.ctx.close();

  const lively = await open({ user: 'lina', reducedMotion: 'no-preference' });
  await lively.page.goto('/#/overview');
  assert.equal(await moving(lively.page, 400), true, 'without the setting the intro plays (the check can see motion)');
  await lively.page.waitForTimeout(4000);
  await lively.page.locator('button[role="switch"]').focus();
  await lively.page.keyboard.press('Space');
  assert.equal(await lively.page.evaluate(() => document.documentElement.dataset.motion), 'reduced');
  await lively.page.goto('/#/policies');
  await settle(lively.page);
  await lively.page.waitForTimeout(300);
  assert.equal(await moving(lively.page, 800), false, 'the console switch stops movement too');
  report('console errors', [...still.errors, ...lively.errors, ...signIn.errors]);
  await lively.ctx.close();
});

test('two-step sign-in: wrong password, QR read by the browser’s own decoder, first code, recovery codes once', { skip: SKIP }, async () => {
  const { hotp, fromBase32 } = await import(resolve(import.meta.dirname, '../../../packages/pdp-http/src/totp.ts')) as { hotp(k: Buffer, step: number): string; fromBase32(s: string): Buffer };
  const { ctx, page, errors } = await open({ user: 'sam' });
  await page.goto('/#/two-step');
  await settle(page);
  await page.locator('#two-step-password').focus();
  await page.keyboard.type('wrong password!');
  await page.keyboard.press('Enter');
  await page.locator('#two-step-password-error').waitFor();
  assert.equal(await page.locator('#two-step-password').getAttribute('aria-invalid'), 'true');
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'two-step-password');
  await page.locator('#two-step-password').fill(server.passwords.sam!);
  await page.keyboard.press('Enter');
  await page.locator('svg.qr-code').waitFor();
  const uri = await page.locator('#two-step-uri').inputValue();
  assert.match(uri, /^otpauth:\/\/totp\//);
  const shot = decodePng(await page.locator('svg.qr-code').screenshot());
  const decoded = await page.evaluate(async (img) => {
    const detector = new (globalThis as unknown as { BarcodeDetector: new (o: object) => { detect(s: ImageData): Promise<{ rawValue: string }[]> } }).BarcodeDetector({ formats: ['qr_code'] });
    const found = await detector.detect(new ImageData(new Uint8ClampedArray(img.rgba), img.width, img.height));
    return found.map((f) => f.rawValue);
  }, { width: shot.width, height: shot.height, rgba: [...shot.rgba] });
  assert.deepEqual(decoded, [uri], 'Chromium’s QR decoder reads the otpauth URI');
  report('enrolment step', await audit(ctx, page, SHELL));

  await page.locator('#two-step-code').fill('12345');
  await page.keyboard.press('Enter');
  await page.locator('#two-step-code-error').waitFor();
  const key = fromBase32(new URL(uri).searchParams.get('secret')!);
  const now = Math.floor(Date.now() / 30_000);
  await page.locator('#two-step-code').fill(hotp(key, now) === '000000' ? '111111' : '000000');
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.getElementById('two-step-code-error')?.textContent?.includes(' '));
  await page.locator('#two-step-code').fill(hotp(key, Math.floor(Date.now() / 30_000)));
  await page.keyboard.press('Enter');
  await page.locator('#two-step-recovery-codes').waitFor();
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'two-step-recovery-title', 'focus moves to the recovery codes');
  const codes = (await page.locator('#two-step-recovery-codes').inputValue()).split('\n');
  assert.equal(codes.length, 10);
  assert.ok(codes.every((c) => /^[a-z0-9]{4}(-[a-z0-9]{4}){3}$/i.test(c)), codes.join(' '));
  assert.match(await page.locator('#two-step-status-title').textContent() ?? '', /On/);
  report('contrast with the recovery codes', (await contrastFailures(page)).failures);
  await page.locator('#two-step-recovery-title ~ .secret-row button:not(.btn-primary)').click();
  assert.equal(await page.locator('#two-step-recovery-codes').count(), 0, 'the codes leave the page');
  report('console errors', errors.filter((e) => !/status of (403|422)/.test(e)));
  await ctx.close();
});

/** Activate a control through the browser's tab order, without moving focus programmatically. */
async function activateByKeyboard(page: Page, selector: string): Promise<void> {
  for (let step = 0; step < 300; step++) {
    await page.keyboard.press('Tab');
    if (await page.evaluate((s) => document.activeElement?.matches(s), selector)) {
      await page.keyboard.press('Enter');
      return;
    }
  }
  assert.fail(`keyboard cannot reach ${selector}`);
}

for (const locale of ['en-GB', 'fr-FR', 'ar-AE']) {
  test(`320 CSS px reflow (1280px at 400% equivalent), landmarks and names: ${locale}`, { skip: SKIP }, async () => {
    const { ctx, page, errors } = await open({ user: 'lina', locale });
    await page.setViewportSize({ width: 320, height: 720 });
    for (const route of ROUTES) {
      await page.goto(`/#/${route}`);
      await settle(page);
      const layout = await page.evaluate(() => {
        const main = document.querySelector('main')!;
        return {
          viewport: innerWidth,
          page: document.documentElement.scrollWidth,
          main: main.clientWidth,
          content: main.scrollWidth,
          headings: main.querySelectorAll('h1').length,
          named: Boolean(main.getAttribute('aria-label')),
        };
      });
      assert.equal(layout.viewport, 320);
      assert.ok(layout.page <= 320, `${route}: page width ${layout.page}`);
      assert.ok(layout.content <= layout.main + 1, `${route}: clipped main content ${JSON.stringify(layout)}`);
      assert.equal(layout.headings, 1, `${route}: one main heading`);
      assert.equal(layout.named, true, `${route}: named main landmark`);
      report(`${route}: names`, (await unnamedControls(ctx, page)).unnamed);
    }
    await page.goto('/#/overview');
    await settle(page);
    await activateByKeyboard(page, '.menu-toggle');
    await activateByKeyboard(page, 'nav a[href="#/simulator"]');
    await settle(page);
    assert.equal(await page.locator('#title-simulator').count(), 1);
    report('console errors', errors);
    await ctx.close();
  });
}

test('forced colours: main workflows retain names, landmarks, selection and keyboard focus', { skip: SKIP }, async () => {
  const { ctx, page, errors } = await open({ user: 'lina', forcedColors: 'active' });
  await page.goto('/#/overview');
  await settle(page);
  assert.equal(await page.evaluate(() => matchMedia('(forced-colors: active)').matches), true);
  for (const route of ROUTES) {
    await activateByKeyboard(page, `nav a[href="#/${route}"]`);
    await settle(page);
    const cdp = await ctx.newCDPSession(page);
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    const landmarks = nodes.filter((n: { ignored: boolean; role?: { value: string } }) => !n.ignored && ['main', 'navigation', 'banner'].includes(n.role?.value ?? ''));
    assert.equal(landmarks.filter((n: { role: { value: string } }) => n.role.value === 'main').length, 1);
    assert.ok(landmarks.some((n: { role: { value: string }; name?: { value: string } }) => n.role.value === 'navigation' && n.name?.value));
    assert.ok(landmarks.some((n: { role: { value: string } }) => n.role.value === 'banner'));
    report(`${route}: names`, (await unnamedControls(ctx, page)).unnamed);
    report(`${route}: keyboard`, (await keyboardWalk(page)).problems);
    assert.equal(await page.evaluate(() => {
      const selected = document.querySelector('a[aria-current="page"]')!;
      const cs = getComputedStyle(selected);
      return cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2;
    }), true, `${route}: selection survives forced colours`);
  }
  report('console errors', errors);
  await ctx.close();
});

test('Arabic RTL layout snapshots: mirrored rail, start alignment, LTR codes and language persistence', { skip: SKIP }, async () => {
  const { ctx, page, errors } = await open({ user: 'lina', locale: 'en-GB' });
  await page.goto('/#/overview');
  await settle(page);
  const snapshot = () => page.evaluate(() => {
    const rail = document.querySelector('.v24-rail')!.getBoundingClientRect();
    const main = document.querySelector('main')!.getBoundingClientRect();
    const code = document.querySelector('main code, main .mono');
    const selected = document.querySelector('.v24-rail [aria-current="page"]')!.getBoundingClientRect();
    const indicator = document.querySelector('.v24-rail-ind')!.getBoundingClientRect();
    return {
      lang: document.documentElement.lang, dir: document.documentElement.dir,
      rail: { left: Math.round(rail.left), right: Math.round(rail.right) },
      main: { left: Math.round(main.left), right: Math.round(main.right) },
      align: getComputedStyle(document.querySelector('.v24-rail-btn')!).textAlign,
      code: code ? getComputedStyle(code).direction : null,
      indicatorOffset: Math.round(indicator.left - selected.left),
    };
  });
  const en = await snapshot();
  await activateByKeyboard(page, 'button[lang="ar"]');
  await page.waitForFunction(() => document.documentElement.dir === 'rtl');
  await settle(page);
  const ar = await snapshot();
  assert.deepEqual({ lang: ar.lang, dir: ar.dir, align: ar.align }, { lang: 'ar', dir: 'rtl', align: 'start' });
  assert.equal(en.indicatorOffset, 0, 'LTR selection indicator aligns');
  assert.equal(ar.indicatorOffset, 0, 'RTL selection indicator aligns');
  assert.ok(en.rail.right < en.main.left, JSON.stringify(en));
  assert.ok(ar.rail.left > ar.main.right, JSON.stringify(ar));
  assert.ok(Math.abs(en.rail.left - (VIEWPORT.width - ar.rail.right)) <= 1, 'rail mirrors around the viewport');
  await page.goto('/#/policies');
  await settle(page);
  assert.equal((await snapshot()).code, 'ltr');
  await page.reload();
  await settle(page);
  assert.equal((await snapshot()).dir, 'rtl');
  await activateByKeyboard(page, 'button[lang="en"]');
  await page.waitForFunction(() => document.documentElement.dir === 'ltr');
  report('console errors', errors);
  await ctx.close();
});
