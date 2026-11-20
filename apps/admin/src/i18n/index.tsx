import { createContext, useContext, type ReactNode } from 'react';
import * as approvals from './approvals';
import * as audit from './audit';
import * as breakGlass from './breakGlass';
import * as common from './common';
import * as compliance from './compliance';
import * as explain from './explain';
import * as integrity from './integrity';
import * as matrix from './matrix';
import * as model from './model';
import * as overview from './overview';
import * as policies from './policies';
import * as reviews from './reviews';
import * as security from './security';
import * as shell from './shell';
import * as signIn from './signIn';
import * as simulator from './simulator';
import * as twoStep from './twoStep';
import * as errors from './errors';
import type { Shape } from './shape';

export type Lang = 'en' | 'fr' | 'ar';
export const LANGS: readonly Lang[] = ['en', 'fr', 'ar'];
/** Each language named in itself, the same in every catalogue. */
export const LANG_NAMES: Readonly<Record<Lang, string>> = { en: 'English', fr: 'Français', ar: 'العربية' };

const en = {
  common: common.en, shell: shell.en, signIn: signIn.en, overview: overview.en, model: model.en, policies: policies.en,
  matrix: matrix.en, explain: explain.en, simulator: simulator.en, approvals: approvals.en, breakGlass: breakGlass.en,
  reviews: reviews.en, audit: audit.en, compliance: compliance.en, security: security.en,
  twoStep: twoStep.en, errors: errors.en, integrity: integrity.en,
};
export type Messages = Shape<typeof en>;
const fr: Messages = {
  common: common.fr, shell: shell.fr, signIn: signIn.fr, overview: overview.fr, model: model.fr, policies: policies.fr,
  matrix: matrix.fr, explain: explain.fr, simulator: simulator.fr, approvals: approvals.fr, breakGlass: breakGlass.fr,
  reviews: reviews.fr, audit: audit.fr, compliance: compliance.fr, security: security.fr,
  twoStep: twoStep.fr, errors: errors.fr, integrity: integrity.fr,
};
const ar: Messages = {
  common: common.ar, shell: shell.ar, signIn: signIn.ar, overview: overview.ar, model: model.ar, policies: policies.ar,
  matrix: matrix.ar, explain: explain.ar, simulator: simulator.ar, approvals: approvals.ar, breakGlass: breakGlass.ar,
  reviews: reviews.ar, audit: audit.ar, compliance: compliance.ar, security: security.ar,
  twoStep: twoStep.ar, errors: errors.ar, integrity: integrity.ar,
};
export const CATALOGUES: Readonly<Record<Lang, Messages>> = { en, fr, ar };

// Helpers outside React (level and role labels, dates) read the language the provider rendered last.
let current: Lang = 'en';
export const msgs = (): Messages => CATALOGUES[current];

const LangContext = createContext<Lang | null>(null);

export function I18nProvider(props: { readonly lang: Lang; readonly children: ReactNode }) {
  current = props.lang;
  return <LangContext.Provider value={props.lang}>{props.children}</LangContext.Provider>;
}

export const useLang = (): Lang => useContext(LangContext) ?? current;
export const useT = (): Messages => CATALOGUES[useLang()];

const KEY = 'qadamar-lang';
const isLang = (v: unknown): v is Lang => v === 'en' || v === 'fr' || v === 'ar';

/** The language this person chose last (per user id), else the last one chosen on this browser, else English. */
export function readLang(userId?: string): Lang {
  try {
    const own = userId ? window.localStorage.getItem(`${KEY}:${userId}`) : null;
    const last = window.localStorage.getItem(KEY);
    if (isLang(own)) return own;
    if (isLang(last)) return last;
  } catch {
    // storage blocked: fall back to English
  }
  return 'en';
}

export function writeLang(userId: string, lang: Lang): void {
  try {
    window.localStorage.setItem(`${KEY}:${userId}`, lang);
    window.localStorage.setItem(KEY, lang);
  } catch {
    // storage blocked: the choice lasts for this page only
  }
}
