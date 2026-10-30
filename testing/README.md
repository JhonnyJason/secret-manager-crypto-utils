# testing

- `test.mjs` tests `output/index.js`, `legacy.test.mjs` tests `output/legacy.js` against the v0.2.0/v0.3.1 fixtures. `fallback.test.mjs` runs it again with native Ed25519/X25519 hidden, so the noble fallback passes the same tests. Same files on every runtime:
  - `node --test testing/`
  - `bun test ./testing/test.mjs ./testing/fallback.test.mjs ./testing/legacy.test.mjs`
  - `deno test -A --no-check testing/test.mjs testing/fallback.test.mjs testing/legacy.test.mjs`
- `fixtures/ed25519-edge.json` (from `make-ed25519-edge-vectors.mjs`): signatures on which raw native Ed25519 (node/bun/deno) and noble disagree - small-order A, small-order R, cofactored-only. Same categories as ed25519-speccheck, but with string messages.
- `fixtures/v0.3.1.json` was produced by the **published** 0.3.1 (node and browser builds) via `make-fixtures.mjs`. Never regenerate it from local code: it is the compatibility contract that old ciphertext keeps decrypting.
- `fixtures/v0.4.0.json` (from `make-v1-fixtures.mjs`, once, from the final 0.4.0 build): v1 symmetric and asymmetric, with and without context. The v1 contract - never regenerate it, the script refuses to overwrite.
- `fixtures/v0.2.0.json`: same, produced by the published 0.2.0. Covers every pre-0.3 format, including `asymmetricOld` (0.2.0's `asymmetricEncryptOld`, which writes the 0.0.x asymmetric format).

## Legacy formats

- `make-legacy-matrix.mjs` cross-checks all published versions: `node testing/make-legacy-matrix.mjs <dir with v<x>/node_modules/secret-manager-crypto-utils>`.
- Findings, exact algorithms and the conversion guide: [legacy-formats.md](./legacy-formats.md).
