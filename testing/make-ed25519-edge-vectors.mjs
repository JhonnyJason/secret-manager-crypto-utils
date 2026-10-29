// node testing/make-ed25519-edge-vectors.mjs > testing/fixtures/ed25519-edge.json
// signatures with string messages in the categories where Ed25519 implementations disagree (ed25519-speccheck, "Taming the many EdDSAs")
import * as ed from "../output/node_modules/@noble/ed25519/index.js"
import { createHash } from "node:crypto"
const G = ed.Point.BASE, I = ed.Point.ZERO, L = ed.Point.CURVE().n
const T8 = ed.Point.fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
const hex = (b) => Buffer.from(b).toString("hex")
const le = (b) => BigInt("0x" + hex(Buffer.from(b).reverse()))
const toLe = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex").reverse()
const k = (R, A, msg) => le(createHash("sha512").update(Buffer.concat([R.toBytes(), A.toBytes(), Buffer.from(msg)])).digest()) % L
const a = 0x0badc0ffeen, r = 0x5eedn
const vector = (name, A, R, S, content, valid) => ({ name, content, keyHex: A.toHex(), sigHex: R.toHex() + hex(toLe(S)), valid })
const mixed = G.multiply(a).add(T8)
// k decides whether k·T8 vanishes: k ≡ 0 mod 8 makes cofactored and cofactorless agree
const findContent = (want) => { for (let i = 0; ; i++) if ((k(G.multiply(r), mixed, "m" + i) % 8n == 0n) == want) return "m" + i }
const c3 = findContent(false), c4 = findContent(true)
console.log(JSON.stringify([
    vector("small-order A (identity): S·G = R verifies any message", I, G.multiply(r), r, "anything", false),
    vector("small-order R (identity)", G.multiply(a), I, k(I, G.multiply(a), "hello") * a % L, "hello", false),
    vector("mixed-order A, k·T8 != 0: only the cofactored equation accepts", mixed, G.multiply(r), (r + k(G.multiply(r), mixed, c3) * a) % L, c3, false),
    vector("mixed-order A, k·T8 == 0: valid under every equation", mixed, G.multiply(r), (r + k(G.multiply(r), mixed, c4) * a) % L, c4, true),
], null, 4))
