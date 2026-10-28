# testing

- `test.mjs` tests `output/index.js`. Same file on every runtime:
  - `node --test testing/`
  - `bun test ./testing/test.mjs`
  - `deno test -A --no-check testing/test.mjs`
- `fixtures/v0.3.1.json` was produced by the **published** 0.3.1 (node and browser builds) via `make-fixtures.mjs`. Never regenerate it from local code: it is the compatibility contract that old ciphertext keeps decrypting.
