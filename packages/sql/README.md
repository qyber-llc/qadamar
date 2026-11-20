# PostgreSQL residual compiler

```ts
import { compile } from './src/index.ts';
const sql = compile(residual, {
  'resource.level': 'level',
  'resource.id': 'id',
  'resource.compartments': { column: 'compartments', kind: 'text[]' },
  'resource.contentClasses': { column: 'content_classes', kind: 'text[]' },
});
// Apply sql.text as WHERE and pass sql.params separately to the database driver.
```

Column strings describe scalar columns; array paths must explicitly use `kind: 'text[]'`.
Identifiers accept one, two or three lowercase identifier segments, each separately quoted.
Unknown paths and invalid mappings throw, including unused invalid mappings. Scalar string
`contains` uses `strpos`, so `%` and `_` are literal characters. Constant expressions fold.
Comparisons preserve SQL three-valued logic, matching core Kleene conditions.
Missing values and JSON null attributes must map to SQL NULL. A path whose JSON type varies by row maps to a JSONB
column with `type: 'jsonb'`: each operator tests `jsonb_typeof` and is NULL on a type mismatch (JSONB `null` counts
as missing), as core's `compare()`; such a path compares with literals only. With typed columns, an ordering,
`contains` or `subset` whose literal cannot match the column type is NULL; `eq`/`ne` across types are FALSE/TRUE. The `unknown` residual
compiles to `NULL::boolean`; negating UNKNOWN remains UNKNOWN, so WHERE drops the row.

Run `node --test packages/sql/test/*.test.ts` from the repository root.
