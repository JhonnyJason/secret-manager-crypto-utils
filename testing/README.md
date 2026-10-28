# testing

- `test.mjs` tests `output/index.js`. Same file on every runtime:
  - `node --test testing/`
  - `bun test ./testing/test.mjs`
  - `deno test -A --no-check testing/test.mjs`
- `fixtures/v0.3.1.json` was produced by the **published** 0.3.1 (node and browser builds) via `make-fixtures.mjs`. Never regenerate it from local code: it is the compatibility contract that old ciphertext keeps decrypting.
- `fixtures/v0.2.0.json`: same, produced by the published 0.2.0. Covers every pre-0.3 format, including `asymmetricOld` (0.2.0's `asymmetricEncryptOld`, which writes the 0.0.x asymmetric format).

## Legacy formats

- `make-legacy-matrix.mjs` cross-checks all published versions: `node testing/make-legacy-matrix.mjs <dir with v<x>/node_modules/secret-manager-crypto-utils>`.
- Findings, exact algorithms and the conversion guide: [legacy-formats.md](./legacy-formats.md).
