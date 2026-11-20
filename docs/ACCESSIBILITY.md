# Admin console accessibility verification

Two layers of tests. Neither is an audit by people with disabilities, and no WCAG conformance claim is made.

```sh
pnpm --filter @product/admin test   # markup and unit tests, no browser
pnpm --filter @product/admin e2e    # builds the console, then the real-browser checks
```

`e2e` needs a local `playwright-core` with its Chromium. `PLAYWRIGHT_CORE_PATH` names it (the older `PLAYWRIGHT_CORE`
still works); unset, `apps/admin/e2e/harness.ts` tries a `playwright-core` resolvable from the repository, then every
copy in `~/.npm/_npx` (newest first, the first whose Chromium starts). Without one every browser test is reported as
skipped, with the reason, and the run stays green; with `E2E_REQUIRED=1` that reason fails the run instead, so a job
that must run the browser tests cannot pass by skipping them:

```sh
E2E_REQUIRED=1 PLAYWRIGHT_CORE_PATH=/path/to/node_modules/playwright-core pnpm --filter @product/admin e2e
```

Playwright remains external tooling, pinned for CI in `tools/ci/playwright-lock.json` ([CI.md](CI.md)).
`tools/ci/checks.sh` now includes the browser suite; CI requires it with `E2E_REQUIRED=1`. Current counts are
reported by each run, not copied here. The complete suite passed locally on 2026-11-11, including the reflow,
forced-colors and Arabic assertions.

## Automated browser coverage (`apps/admin/e2e/console.e2e.ts`)

Chromium (headless, 1280 × 900, device scale 1), against the real PDP server (`packages/pdp-http` `createServer`, file
mode, demo world, fixed demo clock) serving the built console. The demo passwords are read once from
`INITIAL-CREDENTIALS.txt`. English runs with `prefers-color-scheme: light`, French and Arabic with `dark` (the console and the
sign-in page are always dark, so the scheme changes nothing visible). Everything except the motion test runs with
`prefers-reduced-motion: reduce`, so screens are measured at rest.

On the sign-in page and on each of the twelve signed-in screens (Overview, Attribute model, Policies, Access matrix,
Simulator, Approvals, Break-glass, Access reviews, Credentials and keys, Audit, Compliance, Two-step sign-in), signed in
as the security officer (who reaches all of them), in all three languages:

- **No console error and no uncaught exception** while the screen loads. The only accepted error is the browser's log
  line for the expected 401 of the session probe on the sign-in page.
- **`<html lang>`** equals the language.
- **Accessible names**: from Chromium's own accessibility tree (DevTools protocol), every button, link, text box,
  search box, combo box, checkbox, switch, radio, spin button, slider, tab, menu item and list box that is not ignored
  has a non-empty name.
- **Text contrast (WCAG 2.2 SC 1.4.3)**, computed by the test itself (`e2e/contrast.ts`, unit-tested in
  `test/contrast.test.ts`): every visible text node, its line boxes clipped by scrolling ancestors, its colour (alpha
  and ancestor opacity included; SVG text by its fill) composited over the real background pixels, taken from a
  screenshot of the same view with every glyph made transparent, so glass, gradients, images and glows count. The
  ratio kept is the 5th percentile over the sampled pixels; it must reach 4.5:1, or 3:1 for large text (24 px, or
  18.66 px bold). Exempt as WCAG allows: disabled controls, and the product name drawn into the sign-in illustration
  (marked `data-logotype`).
- **Keyboard**: Tab from the top of the document reaches every visible, enabled, focusable control exactly once, in
  document order, with no positive `tabindex`; each one shows a focus indicator (an outline, or a ring, border or
  shadow that differs from its resting style on it or its two parents, read after transitions end); and at its
  centre it is not covered by another element (SC 2.4.11).
- Each check also proves it looked: a minimum number of controls, text nodes and tab stops per screen.

Also verified in the browser:

- **Sign-in with the keyboard alone**: the order is username, password, one-time code, submit; typing and Enter sign
  in; a wrong password marks the fields `aria-invalid` and shows the alert.
- **Language switch**: reached by keyboard; Enter or Space changes `<html lang>`, the text and `aria-pressed`.
- **Dialogs**: the revoke/rotate confirmation and the Simulator's explanation drawer take focus when they open, keep
  it inside on repeated Tab and Shift+Tab, make the page behind inert, and give focus back to the button that opened
  them on Escape; Escape on the Invariants popover returns focus to its button.
- **Reduced motion**: with the system setting, no intro, no running animation longer than 50 ms and no pixel changes
  between two screenshots 0.8 s apart, and the sign-in video does not play; without it the same screenshot check sees
  the intro move (the check can detect motion); the console's own Reduce motion switch, operated by keyboard, stops
  movement too.
- **Two-step sign-in**: a wrong current password gives a field error with `aria-invalid` and focus on the field; the
  QR code is read back by Chromium's own `BarcodeDetector` and equals the otpauth URI shown as text; a malformed and a
  wrong code give field errors; a right code (computed from the secret) turns it on, moves focus to the recovery codes
  (ten), and "I have stored them" removes them from the page; names, contrast and keyboard are checked in the
  enrolment step too.

## Added automated checks

- **Reflow:** all routes in English, French and Arabic at 320 CSS pixels, equivalent to a 1280 CSS-pixel viewport
  at 400% zoom. Assert no document overflow or clipped main container, one main heading, a named main landmark and
  named controls; open the mobile menu and reach Simulator by Tab/Enter. This does not drive the browser's zoom UI.
  Data tables retain their own horizontal scrollers, as permitted for two-dimensional content.
- **Forced colors:** Chromium emulation of `forced-colors: active`, all routes reached by keyboard alone, accessibility
  tree landmarks (banner, named navigation, one main), named controls, tab order and focus visibility, and a non-colour
  current-page outline. This is emulation, not a Windows assistive-technology session.
- **Arabic/RTL:** keyboard language switch, `lang=ar` / `dir=rtl`, persisted choice, mirrored rail geometry against the
  English layout, logical start alignment and LTR code fields. These are deterministic layout snapshots, not image
  golden files. Directional navigation icons mirror; numbers, code and secret fields keep LTR order.

## Verified by markup and unit tests (`apps/admin/test`)

- The original screens render a section labelled by its `h1` and a polite loading status; sign-in fields have
  persistent labels, autocomplete tokens, `required` and initial `aria-invalid`; the shared error state is an alert
  with a native Retry button; empty states are status notices; an open modal renders `role="dialog"`,
  `aria-modal="true"` and its title.
- All three catalogues have the same keys, kinds and arities and no empty messages; every screen, including Credentials
  and keys and Two-step sign-in, renders its heading and loading status in each language; role-based hiding on Credentials.
- Registered inventory (Attribute model, `tab=inventory`) and PEP resource types: the type picker has a persistent
  label; each section is a region named by its `h2`; tables scroll in a focusable, named region; the page range is a
  status line and the previous and next buttons use `aria-disabled` (not `disabled`), so focus stays on them at the
  first and last page; each review link names its change; the resource types of a new PEP credential are a `fieldset`
  with a `legend` and a hint bound by `aria-describedby`. Markup only: the browser pass above does not open this tab yet.
- Every error code the server's `HttpError` and literal error envelopes in `packages/pdp-http/src` can produce, plus
  the console client's own, has a translated message in all three languages (`test/errors.test.ts` greps the source).
- The QR encoder against ISO/IEC 18004 vectors (Annex I Reed-Solomon example, Annex C format and Annex D version
  information, Table 1 module counts) and a reader written from the specification (`test/qr.test.ts`).

## Fixed after the browser tests found them

- The glass window let bright green parts of the backdrop through (`saturate(220%)`): secondary and muted text fell to
  2.3:1 to 4.4:1 over them. The window's backdrop filter now also dims it (`saturate(180%) brightness(0.4)`).
- Access matrix: the denied ✕ was drawn at 0.85 opacity (about 4.1:1); it is now a lighter red at full opacity. A cell
  focused by Tab could scroll under the sticky name column; the scroller now has a matching `scroll-padding-inline-start`.
- Overview: the "Needs your attention" chip was white on a lightened green (4.4:1); its fill now darkens instead.
- Audit: long French detail labels and hashes could not shrink inside their flex rows at 320px. The rows now wrap and
  their children may shrink, keeping the detail card inside the main landmark.

## Not verified

- **No screen reader** (VoiceOver, NVDA, JAWS, TalkBack) has been used: announcements of live regions, the reading
  order and how names and roles are spoken are not tested. Only that names exist in Chromium's tree.
- Only Chromium: no Firefox or Safari, no native browser zoom UI or 200% text-resize test, no text-spacing override
  (SC 1.4.12), and no physical Windows high-contrast session. The 320px reflow and forced-colors checks are emulated
  assertions, not those physical environments.
- Contrast of non-text elements (SC 1.4.11: borders of fields, icons, focus rings), of placeholder text, and of
  hover states is not measured; focus indicators are checked for presence, not for size or contrast (SC 2.4.13).
- Loaded states only as the demo data produces them: empty tables, error states, long names and the session-expired
  dialog are not exercised in the browser; the Approvals and Access reviews forms are not submitted there.
- No native French speaker has reviewed the French text in the running console.

- Native Arabic review is required before customer use, including terminology, reading order and bidirectional mixed text.
