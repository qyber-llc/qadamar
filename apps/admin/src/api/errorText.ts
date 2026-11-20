import type { Messages } from '../i18n';
import { ApiError } from './client';

/** The console's words for a failure: the translated message for the server's stable code (a fallback for an unknown
 *  one), plus the server's own English text as a detail when it says more than the code. */
export function errorText(t: Messages, err: unknown): { readonly text: string; readonly detail?: string } {
  if (err instanceof ApiError) {
    const codes: Readonly<Record<string, string>> = t.errors.codes;
    const text = codes[err.code] ?? t.errors.fallback(err.status);
    const generic = err.message === err.code || err.message.startsWith('Request failed with status');
    return generic ? { text } : { text, detail: err.message };
  }
  if (err instanceof TypeError || (err instanceof DOMException && err.name === 'AbortError')) return { text: t.errors.network };
  return { text: err instanceof Error && err.message ? err.message : t.common.unexpectedError };
}
