/** A catalogue with exactly the keys of T: strings stay strings, message functions keep their parameters. */
export type Shape<T> = {
  readonly [K in keyof T]: T[K] extends string
    ? string
    : T[K] extends (...args: infer A) => string
      ? (...args: A) => string
      : Shape<T[K]>;
};

// Mixed-direction messages must not reorder identifiers or numbers.
export const ltr = (value: string | number): string => value === '' ? '' : `\u2066${value}\u2069`;
