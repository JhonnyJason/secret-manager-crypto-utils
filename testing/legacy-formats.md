# Legacy formats

Spec for the read-only `./legacy` entry point. Its only purpose is **conversion**: read data written by an old version, then re-encrypt or re-sign it with the main (v1) API. Two old versions are still in production, so every function below is needed. Remove the entry point once all stored data is converted.

Evidence:
- `make-legacy-matrix.mjs`: all 15 published versions (node + browser builds) cross-checked against each other (2026-10-29).
- `fixtures/v0.2.0.json` and `fixtures/v0.3.1.json` cover every group.
- Every algorithm below was rebuilt with noble 3 + WebCrypto only and passed 89/89 checks against those fixtures. No old dependency is needed.

## Version → function

| Operation | Written by | Legacy function |
|---|---|---|
| symmetric | 0.0.1 – 0.2.0 | `symmetricDecryptV0_2_0` |
| symmetric | 0.3.0 – 0.3.1 | `symmetricDecryptV0_3_1` |
| asymmetric | 0.0.4 – 0.0.7, and `asymmetricEncryptOld` of 0.1.0 – 0.2.0 | `asymmetricDecryptV0_0_7` |
| asymmetric | 0.1.0 – 0.2.0 | `asymmetricDecryptV0_2_0` |
| asymmetric | 0.3.0 – 0.3.1 | `asymmetricDecryptV0_3_1` |
| signatures | 0.0.2 – 0.2.0 | `verifySignatureV0_2_0` |
| signatures | 0.3.0 – now | main `verifySignature` |
| DH / elGamal raw | 0.2.0 | main again (X25519 since v0.4.0) |
| DH / elGamal hash | 0.2.0 | `diffieHellmanSecretHashV0_2_0` (main binds the public keys since v0.4.0) |
| DH / elGamal | 0.3.0 – 0.3.1 | `diffieHellmanSecretRawV0_3_1`, `diffieHellmanSecretHashV0_3_1` |

A developer who doesn't know which version wrote the data tries the functions of that operation until one succeeds.
- Asymmetric and V0_3_1 symmetric fail loudly: wrong padding or a broken salt throws.
- **V0_2_0 symmetric has no integrity check.** A wrong key can still produce valid PKCS7 padding (~1/256) and return garbage. Try V0_3_1 before V0_2_0, and check that the plaintext makes sense (e.g. `JSON.parse`).

## Shared building blocks

- `scalar(sk)`: `h = sha512(sk)[0:32]`, `h[0] &= 248`, `h[31] &= 127`, `h[31] |= 64`, little-endian → bigint, **mod L**.
  - 0.0.x did not reduce mod L. For prime-order points (every reference point and public key these versions produced) the resulting point is identical. Unreduced scalars throw in noble ≥ 1.6, so always reduce.
- `kA = Point.fromHex(A).multiply(scalar(sk))`. Same Edwards point in every noble version.
- `x25519(kA)`: Montgomery u-coordinate of kA, `u = (1 + y) / (1 − y) mod p` (p = 2^255 − 19), 32 bytes little-endian.
  - This equals noble 1.x `getSharedSecret(sk, A)`, which ran x25519 on the clamped, unreduced head and `A.toX25519()`. For prime-order A, u(head·A) = u((head mod L)·A).
  - noble 3 has no `getSharedSecret`, so compute it from the affine y yourself (modular inverse via `pow(1 − y, p − 2)`).
- `cbc(gibbrish, key)`: AES-256-CBC with PKCS7 (WebCrypto default), `iv = key[0:16]`, `aesKey = key[16:48]`. Key bytes beyond 48 are ignored. Asymmetric passes a 64-byte sha512.
  - **The IV comes from the key**, so it's the same for every message: equal plaintexts give equal ciphertexts. This is one more reason to convert.

## Functions

One export each, the key decides hex or bytes mode like the main API. The Bytes variants of every old version used the same format as the Hex ones.

### `symmetricDecryptV0_2_0(gibbrishHex, keyHex)`
`utf8decode(cbc(gibbrish, key48))`

### `symmetricDecryptV0_3_1(gibbrishHex, keyHex)`
`unsaltContent(cbc(gibbrish, key48))`. Implemented in `sources/source/legacy/legacy.js` (`unsaltContent`, `cbc`).

Salt layout (written by 0.3.x `saltContent`):
- `saltLength = 33 + (rand & 127)` → 33..160 random bytes.
- Then 2 bytes big-endian = sum of all salt bytes, then 1 byte `padding`, then the content, then `padding` bytes (1..32) that mirror the first salt bytes (`b[end − i] == b[i]`). Total length is a multiple of 32.
- `unsalt`: running sum from byte 0, starting the search at idx 32. The first idx where `sum(b[0..idx)) == b[idx]·256 + b[idx+1]` ends the prefix. The search is limited to 160, and a mirror mismatch throws.

### `asymmetricDecryptV0_0_7(secrets, secretKeyHex)`
`symmetricDecryptV0_2_0(encryptedContent, sha512Hex(utf8(kA.toHex())))`
- **It hashes the lowercase hex *string* of the compressed point**, not its bytes.
- The secrets keys are `referencePoint` / `encryptedContent` (0.0.x) or `referencePointHex` / `encryptedContentHex` (`asymmetricEncryptOld`). Accept both.

### `asymmetricDecryptV0_2_0(secrets, secretKeyHex)`
`cbc(encryptedContent, sha512(x25519(kA)))` → utf8.
- Secrets keys `referencePointHex` / `encryptedContentHex`, or `referencePointBytes` / `encryptedContentBytes` from the Bytes API.

### `asymmetricDecryptV0_3_1(secrets, secretKeyHex)`
`symmetricDecryptV0_3_1(encryptedContent, sha512(kA.toBytes()))`. Raw point bytes, unlike V0_0_7.

### `verifySignatureV0_2_0(sigHex, keyHex, content)`
`ed25519.verify(sig, sha256(utf8(content)), key)`. The message is the 32-byte hash, not the content. Same contract as main `verifySignature`: `undefined` if valid, an error string otherwise, never throws.

### `diffieHellmanSecretHashV0_2_0(secretKeyHex, publicKeyHex, context = "")`
- `sha512Hex(x25519(kB) ‖ utf8(context))`, the raw part is main's `diffieHellmanSecretRaw`.
- elGamal recovery (0.2.0 `elGamalSecretHash`): the receiver passes the `referencePointHex`.
- Main hashes `raw ‖ lower publicKey ‖ higher publicKey ‖ utf8(context)` since v0.4.0, so every hashed 0.2.0 secret differs from main.

### `diffieHellmanSecretRawV0_3_1(secretKeyHex, publicKeyHex)` / `diffieHellmanSecretHashV0_3_1(secretKeyHex, publicKeyHex, context = "")`
- Raw: `hex((scalar(sk) · B).toBytes())`, the Edwards point.
- Hash: `sha512Hex(kB.toBytes() ‖ utf8(context))`.
- elGamal recovery (0.3.x `elGamalSecret*`): the receiver calls the same function with their secret key and the `referencePointHex`.
- Main DH is X25519 since v0.4.0 (`x25519(...)`, identical to 0.2.0), so every secret derived with 0.3.x differs from main. Anything keyed by such a secret has to be re-derived.
- Raw 0.2.0 DH/elGamal secrets need no legacy function: main reproduces `fixtures/v0.2.0.json` byte for byte.

## Converting

| Stored data | Read with | Write with |
|---|---|---|
| symmetric ciphertext | `symmetricDecryptV0_3_1`, then `V0_2_0` | `symmetricEncrypt` |
| asymmetric secrets | `asymmetricDecryptV0_3_1` / `V0_2_0` / `V0_0_7` | `asymmetricEncrypt` |
| signature + content | `verifySignatureV0_2_0` | `createSignature` (re-sign with the secret key; a signature can't be converted without it) |
| hashed DH/elGamal key from 0.2.0 | `diffieHellmanSecretHashV0_2_0` | re-derive with main, then re-key whatever the old secret protected |
| DH/elGamal-derived key from 0.3.x | `diffieHellmanSecret*V0_3_1` | re-derive with main, then re-key whatever the old secret protected |

Keys themselves need no conversion: secret and public keys are identical in every version.

## Pitfalls seen in old versions (not formats, don't replicate)
- Never produced output: asymmetric encrypt 0.0.1–0.0.4 node (undefined `securityprimitives`) and 0.0.8–0.0.10 (unreduced scalar). 0.0.8 doesn't load, and neither does the 0.0.9 browser build. Signatures in 0.0.1.
- Broken readers of valid formats: 0.0.x node asymmetric decrypt (`ArrayBuffer` passed to `createHash`), 0.0.1–0.0.5 browser symmetric decrypt, and 0.0.x browser `verify` (missing `await`).
- 0.1.x–0.3.x Bytes functions read `keyBytes.buffer` from offset 0. Pass views at offset 0 when reproducing them.
