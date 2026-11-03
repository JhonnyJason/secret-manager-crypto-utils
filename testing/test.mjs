// run: node --test testing/
import { test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"

const fixture = (name) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"))
const fx = fixture("v0.3.1.json")
// v0.2.0 raw DH = X25519, the same as main again - the hash binds the public keys since v0.4.0
const fx020 = fixture("v0.2.0.json")
// fallback.test.mjs sets a suffix to get a module instance without native Ed25519/X25519
const m = await import("../output/index.js" + (globalThis.moduleSuffix ?? ""))
// pure JS reference for signatures, independent of native Ed25519
const ed = await import("../output/node_modules/@noble/ed25519/index.js")
const hexToBytes = (h) => new Uint8Array(Buffer.from(h, "hex"))
const bytesToHex = (b) => Buffer.from(b).toString("hex")
const { alice, bob, symKeyHex } = fx
// verifySignature resolves undefined when valid, an error string otherwise
const invalid = async (p, msg) => assert.equal(typeof await p, "string", msg)

test(`sha256/sha512 match v0.3.1`, async () => {
    for (const s of fx.sha) {
        assert.equal(await m.sha256(s.content), s.sha256Hex)
        assert.equal(await m.sha512(s.content), s.sha512Hex)
        assert.equal(bytesToHex(await m.sha256Bytes(s.content)), s.sha256Hex)
        assert.equal(bytesToHex(await m.sha512Bytes(s.content)), s.sha512Hex)
    }
})

test(`signatures match v0.3.1 and verify`, async () => {
    for (const s of fx.signatures) {
        assert.equal(await m.createSignature(s.content, alice.secretKeyHex), s.sigHex)
        assert.equal(await m.verifySignature(s.sigHex, alice.publicKeyHex, s.content), undefined)
        assert.equal(await m.verifySignature(hexToBytes(s.sigHex), hexToBytes(alice.publicKeyHex), s.content), undefined)
        assert.equal(await m.verifySignature(s.sigHex, bob.publicKeyHex, s.content), "Invalid signature!")
        assert.equal(await m.verifySignature(s.sigHex, alice.publicKeyHex, s.content + "!"), "Invalid signature!")
        const otherSig = await m.createSignature(s.content + "!", alice.secretKeyHex)
        assert.equal(await m.verifySignature(otherSig, alice.publicKeyHex, s.content), "Invalid signature!")
    }
})

test(`one export per function - only the key-less ones have a …Bytes variant`, () => {
    const names = Object.keys(m).sort()
    assert.deepEqual(names.filter((n) => /(Hex|Bytes)$/.test(n)), ["createKeyPairBytes", "createSymKeyBytes", "sha256Bytes", "sha512Bytes"])
    for (const n of ["verify", "createSharedSecretRaw", "referencedSecretHash", "referencedSharedSecretRaw"]) assert.equal(m[n], undefined, n)
})

test(`the key decides hex or bytes mode, mixed arguments work`, async () => {
    const sk = hexToBytes(alice.secretKeyHex), pk = hexToBytes(alice.publicKeyHex), bobPk = hexToBytes(bob.publicKeyHex)
    const { sigHex, content } = fx.signatures[0]
    assert.equal(bytesToHex(await m.createSignature(content, sk)), sigHex)
    assert.equal(await m.verifySignature(sigHex, pk, content), undefined)
    assert.equal(await m.verifySignature(hexToBytes(sigHex), alice.publicKeyHex, content), undefined)
    const dhHex = await m.diffieHellmanSecretRaw(alice.secretKeyHex, bobPk)
    assert.equal(bytesToHex(await m.diffieHellmanSecretRaw(sk, bob.publicKeyHex)), dhHex)
    const eg = await m.elGamalSecretHash(bobPk, "ctx")
    assert.deepEqual(Object.keys(eg), ["referencePointBytes", "sharedSecretBytes"])
    assert.equal(bytesToHex(eg.sharedSecretBytes), await m.diffieHellmanSecretHash(bob.secretKeyHex, eg.referencePointBytes, "ctx"))
    const kp = await m.createKeyPairBytes()
    assert.equal(bytesToHex(await m.createPublicKey(kp.secretKeyBytes)), bytesToHex(kp.publicKeyBytes))
    const g = await m.symmetricEncrypt("hi", hexToBytes(symKeyHex))
    assert.ok(g instanceof Uint8Array)
    assert.equal(await m.symmetricDecrypt(bytesToHex(g), symKeyHex), "hi")
})

test(`verifySignature never rejects on malformed input`, async () => {
    const { sigHex, content } = fx.signatures[0]
    const sig = hexToBytes(sigHex), key = hexToBytes(alice.publicKeyHex)
    const hexCases = [
        ["zz".repeat(64), alice.publicKeyHex, content],
        [sigHex, alice.publicKeyHex + "x", content],
        [sigHex.slice(2), alice.publicKeyHex, content],
        [sigHex, alice.publicKeyHex.slice(2), content],
        [sigHex, alice.publicKeyHex, "a\uD800b"],
        [null, alice.publicKeyHex, content],
        [sigHex, 42, content],
        [sigHex, alice.publicKeyHex, 42],
        [sigHex, alice.publicKeyHex, undefined],
    ]
    for (const [i, args] of hexCases.entries()) assert.equal(await m.verifySignature(...args), "Malformed input!", `hex ${i}`)
    const bytesCases = [
        [new Uint8Array(63), key, content],
        [sig, new Uint8Array(31), content],
        [sig, key, "x\uD83D"],
        [undefined, undefined, undefined],
    ]
    for (const [i, args] of bytesCases.entries()) await invalid(m.verifySignature(...args), `bytes ${i}`)
})

test(`verifySignature without await is truthy (fails closed)`, async () => {
    const { sigHex, content } = fx.signatures[0]
    const p = m.verifySignature(sigHex, alice.publicKeyHex, content)
    assert.ok(p)
    assert.equal(await p, undefined)
})

test(`public key derivation`, async () => {
    assert.equal(await m.createPublicKey(alice.secretKeyHex), alice.publicKeyHex)
    assert.equal(bytesToHex(await m.createPublicKey(hexToBytes(alice.secretKeyHex))), alice.publicKeyHex)
})

test(`key generation shapes`, async () => {
    const kp = await m.createKeyPair()
    assert.match(kp.secretKeyHex, /^[0-9a-f]{64}$/)
    assert.equal(await m.createPublicKey(kp.secretKeyHex), kp.publicKeyHex)
    assert.match(await m.createSymKey(), /^[0-9a-f]{96}$/)
    assert.equal((await m.createSymKeyBytes()).length, 48)
})

test(`symmetric roundtrip, randomized`, async () => {
    const keyBytes = hexToBytes(symKeyHex)
    for (const c of fx.contents) {
        const a = await m.symmetricEncrypt(c, symKeyHex)
        assert.notEqual(a, await m.symmetricEncrypt(c, symKeyHex))
        assert.equal(await m.symmetricDecrypt(a, symKeyHex), c)
        assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, keyBytes), keyBytes), c)
    }
})

test(`asymmetric roundtrip`, async () => {
    for (const c of fx.contents) {
        const s = await m.asymmetricEncrypt(c, bob.publicKeyHex)
        assert.equal(await m.asymmetricDecrypt(s, bob.secretKeyHex), c)
        const sb = await m.asymmetricEncrypt(c, hexToBytes(bob.publicKeyHex))
        assert.equal(await m.asymmetricDecrypt(sb, hexToBytes(bob.secretKeyHex)), c)
    }
})

test(`raw diffie-hellman matches v0.2.0, both sides agree - the hash differs`, async () => {
    const { alice, bob } = fx020
    for (const d of fx020.diffieHellman) {
        assert.equal(await m.diffieHellmanSecretRaw(alice.secretKeyHex, bob.publicKeyHex), d.rawHex)
        assert.equal(await m.diffieHellmanSecretRaw(bob.secretKeyHex, alice.publicKeyHex), d.rawHex)
        assert.equal(bytesToHex(await m.diffieHellmanSecretRaw(hexToBytes(alice.secretKeyHex), hexToBytes(bob.publicKeyHex))), d.rawHex)
        const h = await m.diffieHellmanSecretHash(alice.secretKeyHex, bob.publicKeyHex, d.context)
        assert.equal(await m.diffieHellmanSecretHash(bob.secretKeyHex, alice.publicKeyHex, d.context), h)
        assert.notEqual(h, d.hashHex)
    }
})

test(`v0.2.0 raw elGamal secrets are recoverable by the receiver`, async () => {
    const { bob } = fx020
    for (const e of fx020.elGamal.filter((e) => e.kind == "raw")) {
        assert.equal(await m.diffieHellmanSecretRaw(bob.secretKeyHex, e.referencePointHex), e.sharedSecretHex, `${e.build}/${e.context}`)
    }
})

// sha512(shared ‖ lower publicKey ‖ higher publicKey ‖ utf8(context))
test(`hashed secrets bind both public keys as transmitted`, async () => {
    const raw = await m.diffieHellmanSecretRaw(alice.secretKeyHex, bob.publicKeyHex)
    const [lo, hi] = [alice.publicKeyHex, bob.publicKeyHex].sort()
    const expected = await m.sha512(hexToBytes(raw + lo + hi + bytesToHex(new TextEncoder().encode("ctx"))))
    assert.equal(await m.diffieHellmanSecretHash(alice.secretKeyHex, bob.publicKeyHex, "ctx"), expected)
    assert.equal(await m.diffieHellmanSecretHash(bob.secretKeyHex, alice.publicKeyHex, "ctx"), expected)
    // -B: the same X25519 secret, another hash
    const minusBob = bob.publicKeyHex.slice(0, 62) + (parseInt(bob.publicKeyHex.slice(62), 16) ^ 0x80).toString(16).padStart(2, "0")
    assert.equal(await m.diffieHellmanSecretRaw(alice.secretKeyHex, minusBob), raw)
    assert.notEqual(await m.diffieHellmanSecretHash(alice.secretKeyHex, minusBob, "ctx"), expected)
    // elGamal: the receiver gets the same hash from the referencePoint
    const e = await m.elGamalSecretHash(bob.publicKeyHex, "ctx")
    const eRaw = await m.diffieHellmanSecretRaw(bob.secretKeyHex, e.referencePointHex)
    const [elo, ehi] = [e.referencePointHex, bob.publicKeyHex].sort()
    assert.equal(e.sharedSecretHex, await m.sha512(hexToBytes(eRaw + elo + ehi + bytesToHex(new TextEncoder().encode("ctx")))))
    assert.equal(await m.diffieHellmanSecretHash(bob.secretKeyHex, e.referencePointHex, "ctx"), e.sharedSecretHex)
})

// v0.3.1 bug: Bytes variants ignored byteOffset (handoff)
test(`symmetric key as subarray view with byteOffset`, async () => {
    const padded = new Uint8Array(64)
    padded.set(hexToBytes(symKeyHex), 16)
    const key = padded.subarray(16)
    const c = fx.contents[2]
    // decrypt with a plain copy: a roundtrip through the same view would hide the bug
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, key), hexToBytes(symKeyHex)), c)
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, symKeyHex), key), c)
})

// WebCrypto rejected shared buffers everywhere and resizable ones on bun, and the fallback's verify reversed a Buffer signature in place
test(`Uint8Array flavors: plain memory gives the same result and is never changed, other memory is a TypeError`, async () => {
    const copyInto = (buffer, b) => { const v = new Uint8Array(buffer); v.set(b); return v }
    const flavors = {
        offset: (b) => { const v = new Uint8Array(b.length + 3); v.set(b, 3); return v.subarray(3) },
    }
    if (globalThis.Buffer?.from) flavors.buffer = (b) => Buffer.from(b)
    const rejected = {
        resizable: (b) => copyInto(new ArrayBuffer(b.length, { maxByteLength: 1024 }), b),
    }
    // browsers have SharedArrayBuffer only when cross-origin isolated
    if (typeof SharedArrayBuffer == "function") rejected.shared = (b) => copyInto(new SharedArrayBuffer(b.length), b)
    if (ArrayBuffer.prototype.transfer) rejected.detached = (b) => { const v = new Uint8Array(b); v.buffer.transfer(); return v }
    const sk = hexToBytes(alice.secretKeyHex), pk = hexToBytes(bob.publicKeyHex), sym = hexToBytes(symKeyHex)
    const sig = await m.createSignature("c", sk), gib = await m.symmetricEncrypt("c", sym)
    const s = await m.asymmetricEncrypt("c", hexToBytes(alice.publicKeyHex))
    // each call takes one argument per position: plain, then each flavor
    const calls = [
        (f) => m.sha256Bytes(f(sym)),
        (f) => m.createPublicKey(f(sk)),
        (f) => m.createSignature("c", f(sk)),
        (f) => m.verifySignature(f(sig), f(hexToBytes(alice.publicKeyHex)), "c"),
        (f) => m.symmetricDecrypt(f(gib), f(sym)),
        (f) => m.symmetricEncrypt("c", f(sym)).then((g) => m.symmetricDecrypt(g, sym)),
        (f) => m.asymmetricDecrypt({ referencePointBytes: f(s.referencePointBytes), encryptedContentBytes: f(s.encryptedContentBytes) }, f(hexToBytes(alice.secretKeyHex))),
        (f) => m.asymmetricEncrypt("c", f(pk)).then((r) => r.referencePointBytes.length),
        (f) => m.diffieHellmanSecretRaw(f(sk), f(pk)),
        (f) => m.diffieHellmanSecretHash(f(sk), f(pk), "ctx"),
        (f) => m.elGamalSecretHash(f(pk), "ctx").then((r) => r.sharedSecretBytes.length),
    ]
    for (const [i, call] of calls.entries()) {
        const expected = await call((b) => b)
        for (const [name, flavor] of Object.entries(flavors)) {
            const inputs = []
            const f = (b) => { const v = flavor(b); inputs.push([v, bytesToHex(v)]); return v }
            assert.deepEqual(await call(f), expected, `call ${i}, ${name}`)
            for (const [v, before] of inputs) assert.equal(bytesToHex(v), before, `call ${i}, ${name}: input changed`)
        }
        for (const [name, flavor] of Object.entries(rejected)) {
            // verifySignature never throws, it answers
            if (i == 3) assert.equal(await call(flavor), "Malformed input!", name)
            else await assert.rejects(call(flavor), TypeError, `call ${i}, ${name}`)
        }
    }
    // only Uint8Array: the shas took ArrayBuffer and DataView before
    for (const bad of [sym.buffer, new DataView(sym.buffer), new Uint8ClampedArray(sym)]) await assert.rejects(m.sha256(bad), TypeError)
})

//############################################################
// format v1: 0x01 ‖ nonce(12) ‖ GCM( padLen(1) ‖ content ‖ random(padLen) ) ‖ tag(16)
const keyBytes = hexToBytes(symKeyHex)
const encrypt = (c) => m.symmetricEncrypt(c, keyBytes)
const rejects = (bytes, key = keyBytes) => assert.rejects(m.symmetricDecrypt(bytes, key), /Decryption failed/)

test(`v1 layout and length bounds`, async () => {
    for (const c of fx.contents) {
        const contentLength = new TextEncoder().encode(c).length
        const g = await encrypt(c)
        assert.equal(g[0], 0x01)
        const padLength = g.length - (1 + 12 + 16 + 1 + contentLength)
        assert.ok(padLength >= 0 && padLength <= 255, `padLength ${padLength}`)
    }
})

test(`v1 padded lengths vary`, async () => {
    const lengths = new Set()
    for (let i = 0; i < 50; i++) lengths.add((await encrypt("a")).length)
    assert.ok(lengths.size > 10, `only ${lengths.size} distinct lengths`)
})

test(`v1 any single bit flip is rejected`, async () => {
    for (const c of ["", fx.contents[3]]) {
        const g = await encrypt(c)
        for (let bit = 0; bit < g.length * 8; bit++) {
            const t = g.slice()
            t[bit >> 3] ^= 1 << (bit & 7)
            await rejects(t)
        }
    }
})

test(`v1 truncation, wrong key and empty input are rejected`, async () => {
    const g = await encrypt(fx.contents[2])
    for (const cut of [1, 15, 16, g.length - 13, g.length - 1, g.length]) await rejects(g.subarray(0, g.length - cut))
    const otherKey = keyBytes.slice()
    otherKey[20] ^= 1
    await rejects(g, otherKey)
})

test(`v1 ignores key bytes 0..15`, async () => {
    const g = await encrypt(fx.contents[2])
    const otherKey = keyBytes.slice()
    otherKey.fill(0, 0, 16)
    assert.equal(await m.symmetricDecrypt(g, otherKey), fx.contents[2])
})

// frozen v1 output of v0.4.0 (make-v1-fixtures.mjs): every later version must keep reading it
test(`v0.4.0 v1 fixture decrypts, with and without context`, async () => {
    const fx040 = fixture("v0.4.0.json")
    for (const e of fx040.symmetric) {
        assert.equal(await m.symmetricDecrypt(e.gibbrishHex, fx040.symKeyHex, e.context), e.content, e.context)
        assert.equal(await m.symmetricDecrypt(hexToBytes(e.gibbrishHex), hexToBytes(fx040.symKeyHex), e.context), e.content)
    }
    for (const e of fx040.asymmetric) {
        assert.equal(await m.asymmetricDecrypt(e, fx040.bob.secretKeyHex, e.context), e.content, e.context)
    }
    await assert.rejects(m.symmetricDecrypt(fx040.symmetric.at(-1).gibbrishHex, fx040.symKeyHex), /Decryption failed/)
})

//############################################################
// context: GCM additionalData
test(`context roundtrips, wrong or missing context is rejected`, async () => {
    const c = fx.contents[2]
    const g = await m.symmetricEncrypt(c, symKeyHex, "ctx")
    assert.equal(await m.symmetricDecrypt(g, symKeyHex, "ctx"), c)
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, keyBytes, "ctx"), keyBytes, "ctx"), c)
    for (const other of [undefined, "", "ctX", "ctx "]) await assert.rejects(m.symmetricDecrypt(g, symKeyHex, other), /Decryption failed/, String(other))
    await assert.rejects(m.symmetricDecrypt(await m.symmetricEncrypt(c, symKeyHex), symKeyHex, "ctx"), /Decryption failed/)

    const s = await m.asymmetricEncrypt(c, bob.publicKeyHex, "ctx")
    assert.equal(await m.asymmetricDecrypt(s, bob.secretKeyHex, "ctx"), c)
    await assert.rejects(m.asymmetricDecrypt(s, bob.secretKeyHex), /Decryption failed/)
    await assert.rejects(m.asymmetricDecrypt(s, bob.secretKeyHex, "other"), /Decryption failed/)
    const sb = await m.asymmetricEncrypt(c, hexToBytes(bob.publicKeyHex), "ctx")
    assert.equal(await m.asymmetricDecrypt(sb, hexToBytes(bob.secretKeyHex), "ctx"), c)
    await assert.rejects(m.asymmetricDecrypt(sb, hexToBytes(bob.secretKeyHex)), /Decryption failed/)
})

test(`empty context is the same as no context`, async () => {
    const c = fx.contents[2]
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, symKeyHex, ""), symKeyHex), c)
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, symKeyHex), symKeyHex, ""), c)
    assert.equal(await m.asymmetricDecrypt(await m.asymmetricEncrypt(c, bob.publicKeyHex, ""), bob.secretKeyHex), c)
    // sealed without any additionalData: today's v1 output still decrypts
    const key = await crypto.subtle.importKey("raw", keyBytes.subarray(16, 48), "AES-GCM", false, ["encrypt"])
    const nonce = new Uint8Array(12)
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new Uint8Array([0, 104, 105])))
    assert.equal(await m.symmetricDecrypt(new Uint8Array([0x01, ...nonce, ...sealed]), keyBytes, ""), "hi")
})

test(`context must be a well-formed string`, async () => {
    for (const bad of ["a\uD800b", 42, null]) {
        await assert.rejects(m.symmetricEncrypt("x", symKeyHex, bad), TypeError, String(bad))
        await assert.rejects(m.symmetricDecrypt(await m.symmetricEncrypt("x", symKeyHex), symKeyHex, bad), TypeError)
    }
})

//############################################################
// KDF: PBKDF2-SHA256, 48 bytes
test(`KDF matches PBKDF2-SHA256 known answer`, async () => {
    const saltHex = "00112233445566778899aabbccddeeff"
    // = pbkdf2Sync("correct horse", salt, 1000, 48, "sha256") in node and python hashlib
    const expected = "4c5805526868c915a4cba43d75ec6b0a07152bb7b9ca30501c96ea0f9188682988bd36490462762c07fbd8f4263bc49f"
    assert.deepEqual(await m.deriveSymKeyFromPassword("correct horse", saltHex, 1000), { keyHex: expected, saltHex, iterations: 1000 })
    // hex output is always lowercase, also the salt we were given
    assert.deepEqual(await m.deriveSymKeyFromPassword("correct horse", saltHex.toUpperCase(), 1000), { keyHex: expected, saltHex, iterations: 1000 })
})

test(`KDF defaults: random 16 byte salt, 600000 iterations, key works`, async () => {
    const a = await m.deriveSymKeyFromPassword("pin1234")
    assert.equal(a.iterations, 600000)
    assert.match(a.saltHex, /^[0-9a-f]{32}$/)
    assert.match(a.keyHex, /^[0-9a-f]{96}$/)
    assert.notEqual(a.saltHex, (await m.deriveSymKeyFromPassword("pin1234", undefined, 1000)).saltHex)
    assert.equal((await m.deriveSymKeyFromPassword("pin1234", a.saltHex)).keyHex, a.keyHex)
    assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt("secret", a.keyHex), a.keyHex), "secret")
})

test(`KDF normalizes unicode (NFC)`, async () => {
    const salt = "00".repeat(16)
    const composed = await m.deriveSymKeyFromPassword("café", salt, 1000)
    const decomposed = await m.deriveSymKeyFromPassword("café", salt, 1000)
    assert.equal(composed.keyHex, decomposed.keyHex)
})

//############################################################
// input validation at the boundary
test(`invalid hex is rejected`, async () => {
    for (const bad of ["abc", "zz".repeat(32), "0x" + "00".repeat(31)]) {
        await assert.rejects(async () => m.createPublicKey(bad), SyntaxError, String(bad))
    }
    // not a string means bytes mode
    for (const bad of [null, 42]) await assert.rejects(async () => m.createPublicKey(bad), TypeError, String(bad))
    await assert.rejects(async () => m.symmetricDecrypt("0g", symKeyHex), SyntaxError)
})

test(`symmetric keys shorter than 48 bytes are rejected`, async () => {
    for (const len of [0, 32, 40, 47]) {
        await assert.rejects(m.symmetricEncrypt("x", keyBytes.subarray(0, len)), RangeError, `len ${len}`)
        await assert.rejects(m.symmetricDecrypt(await encrypt("x"), keyBytes.subarray(0, len)), RangeError)
    }
    await assert.rejects(m.symmetricEncrypt("x", undefined), TypeError)
})

test(`symmetric decrypt rejects non-Uint8Array input with TypeError`, async () => {
    const g = await encrypt("x")
    for (const bad of [undefined, 42, Array.from(g), g.buffer]) {
        await assert.rejects(m.symmetricDecrypt(bad, keyBytes), TypeError)
        await assert.rejects(m.symmetricDecrypt(g, bad), TypeError)
    }
})

test(`ed25519 lengths are enforced`, async () => {
    await assert.rejects(m.createSignature("c", new Uint8Array(31)), RangeError)
    await assert.rejects(m.diffieHellmanSecretRaw(new Uint8Array(33), hexToBytes(bob.publicKeyHex)), RangeError)
    for (const len of [0, 31, 33]) await assert.rejects(m.createPublicKey(new Uint8Array(len)), RangeError, `len ${len}`)
})

test(`KDF rejects bad iterations and salt`, async () => {
    for (const it of [0, -1, 1.5, "1000", 999, 10000001]) await assert.rejects(m.deriveSymKeyFromPassword("pw", "00".repeat(16), it), RangeError, String(it))
    await assert.rejects(m.deriveSymKeyFromPassword("pw", "xyz", 1000), SyntaxError)
    for (const salt of [null, 42, new Uint8Array(16)]) await assert.rejects(m.deriveSymKeyFromPassword("pw", salt, 1000), TypeError, String(salt))
})

test(`asymmetric v1 tamper is rejected`, async () => {
    const s = await m.asymmetricEncrypt(fx.contents[3], hexToBytes(bob.publicKeyHex))
    s.encryptedContentBytes[20] ^= 1
    await assert.rejects(m.asymmetricDecrypt(s, hexToBytes(bob.secretKeyHex)), /Decryption failed/)
})

test(`v1 nonces are fresh per message`, async () => {
    const nonces = new Set()
    for (let i = 0; i < 50; i++) nonces.add(bytesToHex((await encrypt("a")).subarray(1, 13)))
    assert.equal(nonces.size, 50)
})

test(`v1 authentic but malformed padding is rejected`, async () => {
    // seals arbitrary plaintext with the real key: only the padLen check can catch this
    const key = await crypto.subtle.importKey("raw", keyBytes.subarray(16, 48), "AES-GCM", false, ["encrypt"])
    const seal = async (plain) => {
        const nonce = crypto.getRandomValues(new Uint8Array(12))
        const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain))
        return new Uint8Array([0x01, ...nonce, ...sealed])
    }
    assert.equal(await m.symmetricDecrypt(await seal(new Uint8Array([2, 104, 105, 0, 0])), keyBytes), "hi")
    for (const plain of [[1], [5, 104, 105], [255]]) await rejects(await seal(new Uint8Array(plain)))
})

//############################################################
// small-order points: identity, order 2, order 4, order 8
const smallOrder = [
    "01" + "00".repeat(31),
    "ec" + "ff".repeat(30) + "7f",
    "00".repeat(32),
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
]

test(`small-order public keys are rejected`, async () => {
    for (const p of smallOrder) {
        // R = identity, S = 0 verifies any message under zip215 with a small-order key
        await invalid(m.verifySignature(smallOrder[0] + "00".repeat(32), p, "anything"), p)
        await assert.rejects(m.diffieHellmanSecretRaw(bob.secretKeyHex, p), RangeError, p)
        await assert.rejects(m.diffieHellmanSecretHash(bob.secretKeyHex, p, "ctx"), RangeError)
        await assert.rejects(m.elGamalSecretRaw(p), RangeError)
        await assert.rejects(m.elGamalSecretHash(p, "ctx"), RangeError)
        await assert.rejects(m.asymmetricEncrypt("x", p), RangeError)
        const s = await m.asymmetricEncrypt("x", bob.publicKeyHex)
        await assert.rejects(m.asymmetricDecrypt({ ...s, referencePointHex: p }, bob.secretKeyHex), RangeError)
    }
})

// y = 2 is not on the curve, y = p is non-canonical, 31 bytes is the wrong length: RangeError, not noble's plain Error
test(`invalid public keys and reference points are a RangeError`, async () => {
    const s = await m.asymmetricEncrypt("x", bob.publicKeyHex)
    for (const p of ["02" + "00".repeat(31), "ed" + "ff".repeat(30) + "7f", "00".repeat(31)]) {
        await assert.rejects(m.diffieHellmanSecretRaw(bob.secretKeyHex, p), RangeError, p)
        await assert.rejects(m.diffieHellmanSecretHash(bob.secretKeyHex, p, "ctx"), RangeError, p)
        await assert.rejects(m.elGamalSecretRaw(p), RangeError, p)
        await assert.rejects(m.elGamalSecretHash(p, "ctx"), RangeError, p)
        await assert.rejects(m.asymmetricEncrypt("x", p), RangeError, p)
        await assert.rejects(m.asymmetricDecrypt({ ...s, referencePointHex: p }, bob.secretKeyHex), RangeError, p)
    }
    for (const p of [null, 42, [1, 2]]) await assert.rejects(m.elGamalSecretRaw(p), TypeError, String(p))
})

// bob's public key + the order-8 point: not small-order, but not torsion-free either
const bobPlusT8 = "f7f44d8ed83ce9887a1aa98973af07aeb60b94727755a55b03c5254382422952"

// X25519 clamping makes the scalar a multiple of 8: the torsion component drops out, nothing about k mod 8 leaks
// the hashed secrets bind the key as transmitted, so B + T8 gives another hash than bob's own key
test(`a torsion component of a public key has no effect on the raw secret`, async () => {
    assert.equal(await m.diffieHellmanSecretRaw(alice.secretKeyHex, bobPlusT8), await m.diffieHellmanSecretRaw(alice.secretKeyHex, bob.publicKeyHex))
    assert.notEqual(await m.diffieHellmanSecretHash(alice.secretKeyHex, bobPlusT8, "ctx"), await m.diffieHellmanSecretHash(alice.secretKeyHex, bob.publicKeyHex, "ctx"))
    const e = await m.elGamalSecretHash(bobPlusT8, "ctx")
    assert.notEqual(await m.diffieHellmanSecretHash(bob.secretKeyHex, e.referencePointHex, "ctx"), e.sharedSecretHex)
    assert.equal(await m.asymmetricDecrypt(await m.asymmetricEncrypt("x", bobPlusT8), bob.secretKeyHex), "x")
})

test(`verifySignature is strict: non-canonical encodings and malleable S rejected`, async () => {
    const s = fx.signatures[1]
    // identity with y = p + 1, only decodable in zip215 mode
    await invalid(m.verifySignature(smallOrder[0] + "00".repeat(32), "ee" + "ff".repeat(30) + "7f", "anything"))
    // S + L: same signature in a second encoding
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    const S = BigInt("0x" + Buffer.from(s.sigHex.slice(64), "hex").reverse().toString("hex"))
    const sPlusL = Buffer.from((S + L).toString(16).padStart(64, "0"), "hex").reverse().toString("hex")
    await invalid(m.verifySignature(s.sigHex.slice(0, 64) + sPlusL, alice.publicKeyHex, s.content))
})

// raw native implementations and noble disagree on these (make-ed25519-edge-vectors.mjs), main must not
test(`verifySignature edge-case vectors give the same answer everywhere`, async () => {
    for (const v of fixture("ed25519-edge.json")) {
        assert.equal(await m.verifySignature(v.sigHex, v.keyHex, v.content) === undefined, v.valid, v.name)
    }
})

test(`non-ASCII and large content roundtrip`, async () => {
    const contents = ["Grüße, Müßiggänger", "🔐🗝️👩‍👩‍👧", "秘密の鍵", "€".repeat(350000)]
    for (const c of contents) {
        assert.equal(await m.symmetricDecrypt(await m.symmetricEncrypt(c, symKeyHex), symKeyHex), c)
        assert.equal(await m.asymmetricDecrypt(await m.asymmetricEncrypt(c, bob.publicKeyHex), bob.secretKeyHex), c)
        assert.equal(await m.verifySignature(await m.createSignature(c, alice.secretKeyHex), alice.publicKeyHex, c), undefined)
    }
})

// WebKitGTK's native Ed25519 broke from about 65000 bytes - WebKit takes noble from 32 KiB, native must be right below at every size
test(`signatures of every size match noble, verify, and reject a flipped bit`, async () => {
    const sizes = new Set([0, 32767, 32768, 40000, 65000, 65535, 65536, 100000])
    for (let p = 1; p <= 65536; p *= 2) [p - 1, p, p + 1].forEach((n) => sizes.add(n))
    for (let n = 0; n < 32768; n += 1021) sizes.add(n)
    const sk = hexToBytes(alice.secretKeyHex)
    for (const n of [...sizes].sort((a, b) => a - b)) {
        const c = "a".repeat(n)
        const sig = await m.createSignature(c, alice.secretKeyHex)
        assert.equal(sig, bytesToHex(await ed.signAsync(new TextEncoder().encode(c), sk)), `size ${n}`)
        assert.equal(await m.verifySignature(sig, alice.publicKeyHex, c), undefined, `size ${n}`)
        const bad = (parseInt(sig[0], 16) ^ 1).toString(16) + sig.slice(1)
        assert.equal(await m.verifySignature(bad, alice.publicKeyHex, c), "Invalid signature!", `size ${n} flipped`)
    }
})

test(`lone surrogates are rejected`, async () => {
    for (const bad of ["a\uD800b", "\uDC00", "x\uD83D"]) {
        await assert.rejects(m.symmetricEncrypt(bad, symKeyHex), TypeError)
        await assert.rejects(m.asymmetricEncrypt(bad, bob.publicKeyHex), TypeError)
        await assert.rejects(m.createSignature(bad, alice.secretKeyHex), TypeError)
        await assert.rejects(m.sha256(bad), TypeError)
        await assert.rejects(m.diffieHellmanSecretHash(alice.secretKeyHex, bob.publicKeyHex, bad), TypeError)
        await assert.rejects(m.deriveSymKeyFromPassword(bad, "00".repeat(16), 1000), TypeError)
    }
    await assert.rejects(m.symmetricEncrypt(new Uint8Array([1, 2]), keyBytes), TypeError)
})

test(`KDF rejects salts shorter than 16 bytes`, async () => {
    for (const salt of ["", "00", "00".repeat(15)]) await assert.rejects(m.deriveSymKeyFromPassword("pw", salt, 1000), RangeError, salt)
})

test(`asymmetric referencePoint bit flips are rejected`, async () => {
    const s = await m.asymmetricEncrypt(fx.contents[3], hexToBytes(bob.publicKeyHex))
    for (let bit = 0; bit < 256; bit++) {
        const referencePointBytes = s.referencePointBytes.slice()
        referencePointBytes[bit >> 3] ^= 1 << (bit & 7)
        // not on the curve, small-order, or a valid point giving the wrong key
        // bit 255 is the sign of x: -A gives the same X25519 secret, only sha512(shared ‖ A) makes the key differ
        await assert.rejects(m.asymmetricDecrypt({ ...s, referencePointBytes }, hexToBytes(bob.secretKeyHex)), /Invalid public key|Decryption failed/, `bit ${bit}`)
    }
})

test(`uppercase hex is accepted`, async () => {
    const g = await m.symmetricEncrypt("x", symKeyHex)
    assert.equal(await m.symmetricDecrypt(g.toUpperCase(), symKeyHex.toUpperCase()), "x")
    assert.equal(await m.createPublicKey(alice.secretKeyHex.toUpperCase()), alice.publicKeyHex)
    const s = fx.signatures[0]
    assert.equal(await m.verifySignature(s.sigHex.toUpperCase(), alice.publicKeyHex.toUpperCase(), s.content), undefined)
})

test(`every function rejects invalid hex`, async () => {
    const bad = "zz".repeat(32)
    const calls = [
        () => m.createPublicKey(bad),
        () => m.createSignature("c", bad),
        () => m.symmetricEncrypt("c", bad + bad),
        () => m.symmetricDecrypt(bad, symKeyHex),
        () => m.symmetricDecrypt("00", bad + bad),
        () => m.asymmetricEncrypt("c", bad),
        () => m.asymmetricDecrypt({ referencePointHex: bad, encryptedContentHex: "00" }, bob.secretKeyHex),
        () => m.asymmetricDecrypt({ referencePointHex: alice.publicKeyHex, encryptedContentHex: bad }, bob.secretKeyHex),
        () => m.asymmetricDecrypt({ referencePointHex: alice.publicKeyHex, encryptedContentHex: "00" }, bad),
        () => m.diffieHellmanSecretRaw(bad, bob.publicKeyHex),
        () => m.diffieHellmanSecretRaw(alice.secretKeyHex, bad),
        () => m.diffieHellmanSecretHash(bad, bob.publicKeyHex),
        () => m.diffieHellmanSecretHash(alice.secretKeyHex, bad),
        () => m.elGamalSecretRaw(bad),
        () => m.elGamalSecretHash(bad),
        () => m.deriveSymKeyFromPassword("pw", bad, 1000),
    ]
    for (const [i, call] of calls.entries()) await assert.rejects(async () => call(), SyntaxError, `call ${i}`)
})

test(`asymmetricDecrypt rejects secrets without referencePoint or encryptedContent`, async () => {
    const s = await m.asymmetricEncrypt("c", bob.publicKeyHex)
    for (const bad of [{}, 42, "str", { referencePointHex: s.referencePointHex }, { encryptedContentHex: s.encryptedContentHex }]) {
        await assert.rejects(m.asymmetricDecrypt(bad, bob.secretKeyHex), /Invalid secrets Object/, JSON.stringify(bad))
    }
    for (const bad of [null, undefined]) await assert.rejects(m.asymmetricDecrypt(bad, bob.secretKeyHex), TypeError, String(bad))
})

// the one guarantee about errors: whatever fails rejects with an Error, never with something else
test(`every rejection is an Error`, async () => {
    const bad = [undefined, null, 42, "", "zz", {}, new Uint8Array(0), new Uint8Array(64), "a\uD800"]
    for (const [name, fn] of Object.entries(m)) {
        for (const x of bad) await fn(x, x, x).then(() => {}, (e) => assert.ok(e instanceof Error, `${name}(${String(x)}): ${e}`))
    }
})
