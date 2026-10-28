// run: node --test testing/
import { test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import { pbkdf2Sync } from "node:crypto"

const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/v0.3.1.json", import.meta.url), "utf8"))
const m = await import("../output/index.js")
const hexToBytes = (h) => new Uint8Array(Buffer.from(h, "hex"))
const bytesToHex = (b) => Buffer.from(b).toString("hex")
const { alice, bob, symKeyHex } = fx

test(`sha256/sha512 match v0.3.1`, async () => {
    for (const s of fx.sha) {
        assert.equal(await m.sha256Hex(s.content), s.sha256Hex)
        assert.equal(await m.sha512Hex(s.content), s.sha512Hex)
        assert.equal(bytesToHex(await m.sha256Bytes(s.content)), s.sha256Hex)
        assert.equal(bytesToHex(await m.sha512Bytes(s.content)), s.sha512Hex)
    }
})

test(`signatures match v0.3.1 and verify`, async () => {
    for (const s of fx.signatures) {
        assert.equal(await m.createSignatureHex(s.content, alice.secretKeyHex), s.sigHex)
        assert.equal(await m.verifyHex(s.sigHex, alice.publicKeyHex, s.content), true)
        assert.equal(await m.verifyBytes(hexToBytes(s.sigHex), hexToBytes(alice.publicKeyHex), s.content), true)
        assert.equal(await m.verifyHex(s.sigHex, bob.publicKeyHex, s.content), false)
        assert.equal(await m.verifyHex(s.sigHex, alice.publicKeyHex, s.content + "!"), false)
    }
})

test(`public key derivation`, async () => {
    assert.equal(await m.createPublicKeyHex(alice.secretKeyHex), alice.publicKeyHex)
    assert.equal(bytesToHex(await m.createPublicKeyBytes(hexToBytes(alice.secretKeyHex))), alice.publicKeyHex)
})

test(`key generation shapes`, async () => {
    const kp = await m.createKeyPairHex()
    assert.match(kp.secretKeyHex, /^[0-9a-f]{64}$/)
    assert.equal(await m.createPublicKeyHex(kp.secretKeyHex), kp.publicKeyHex)
    assert.match(await m.createSymKeyHex(), /^[0-9a-f]{96}$/)
    assert.equal((await m.createSymKeyBytes()).length, 48)
})

test(`legacy symmetric ciphertext decrypts`, async () => {
    for (const s of fx.symmetric) {
        assert.equal(await m.symmetricDecryptHex(s.gibbrishHex, symKeyHex), s.content, `${s.build}/${s.variant}`)
        assert.equal(await m.symmetricDecryptBytes(hexToBytes(s.gibbrishHex), hexToBytes(symKeyHex)), s.content)
    }
})

test(`legacy asymmetric secrets decrypt`, async () => {
    for (const s of fx.asymmetric) {
        const { referencePointHex, encryptedContentHex } = s
        assert.equal(await m.asymmetricDecryptHex({ referencePointHex, encryptedContentHex }, bob.secretKeyHex), s.content, `${s.build}/${s.variant}`)
        const secrets = { referencePointBytes: hexToBytes(referencePointHex), encryptedContentBytes: hexToBytes(encryptedContentHex) }
        assert.equal(await m.asymmetricDecryptBytes(secrets, hexToBytes(bob.secretKeyHex)), s.content)
    }
})

test(`symmetric roundtrip, randomized`, async () => {
    const keyBytes = hexToBytes(symKeyHex)
    for (const c of fx.contents) {
        const a = await m.symmetricEncryptHex(c, symKeyHex)
        assert.notEqual(a, await m.symmetricEncryptHex(c, symKeyHex))
        assert.equal(await m.symmetricDecryptHex(a, symKeyHex), c)
        assert.equal(await m.symmetricDecryptBytes(await m.symmetricEncryptBytes(c, keyBytes), keyBytes), c)
    }
})

test(`asymmetric roundtrip`, async () => {
    for (const c of fx.contents) {
        const s = await m.asymmetricEncryptHex(c, bob.publicKeyHex)
        assert.equal(await m.asymmetricDecryptHex(s, bob.secretKeyHex), c)
        const sb = await m.asymmetricEncryptBytes(c, hexToBytes(bob.publicKeyHex))
        assert.equal(await m.asymmetricDecryptBytes(sb, hexToBytes(bob.secretKeyHex)), c)
    }
})

test(`diffie-hellman matches v0.3.1, both sides agree`, async () => {
    for (const d of fx.diffieHellman) {
        assert.equal(await m.diffieHellmanSecretHashHex(alice.secretKeyHex, bob.publicKeyHex, d.context), d.hashHex)
        assert.equal(await m.diffieHellmanSecretHashHex(bob.secretKeyHex, alice.publicKeyHex, d.context), d.hashHex)
        assert.equal(await m.diffieHellmanSecretRawHex(bob.secretKeyHex, alice.publicKeyHex), d.rawHex)
        const hb = await m.diffieHellmanSecretHashBytes(hexToBytes(alice.secretKeyHex), hexToBytes(bob.publicKeyHex), d.context)
        assert.equal(bytesToHex(hb), d.hashHex)
    }
})

test(`legacy elGamal secrets are recoverable by the receiver`, async () => {
    for (const e of fx.elGamal) {
        const recovered = e.kind == "hash"
            ? await m.diffieHellmanSecretHashHex(bob.secretKeyHex, e.referencePointHex, e.context)
            : await m.diffieHellmanSecretRawHex(bob.secretKeyHex, e.referencePointHex)
        assert.equal(recovered, e.sharedSecretHex, `${e.build}/${e.kind}/${e.context}`)
    }
})

// v0.3.1 bug: Bytes variants ignored byteOffset (handoff)
test(`symmetric key as subarray view with byteOffset`, async () => {
    const padded = new Uint8Array(64)
    padded.set(hexToBytes(symKeyHex), 16)
    const key = padded.subarray(16)
    const c = fx.contents[2]
    // decrypt with a plain copy: a roundtrip through the same view would hide the bug
    assert.equal(await m.symmetricDecryptBytes(await m.symmetricEncryptBytes(c, key), hexToBytes(symKeyHex)), c)
    assert.equal(await m.symmetricDecryptBytes(hexToBytes(fx.symmetric[0].gibbrishHex), key), fx.symmetric[0].content)
})

//############################################################
// format v1: 0x01 ‖ nonce(12) ‖ GCM( padLen(1) ‖ content ‖ random(padLen) ) ‖ tag(16)
const keyBytes = hexToBytes(symKeyHex)
const encrypt = (c) => m.symmetricEncryptBytes(c, keyBytes)
const rejects = (bytes, key = keyBytes) => assert.rejects(m.symmetricDecryptBytes(bytes, key), /Decryption failed/)

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

test(`legacy ciphertext starting with 0x01 falls back to CBC`, async () => {
    const prefixed = fx.symmetric.filter((s) => s.gibbrishHex.startsWith("01"))
    assert.ok(prefixed.length > 0)
    for (const s of prefixed) assert.equal(await m.symmetricDecryptHex(s.gibbrishHex, symKeyHex), s.content)
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
    assert.equal(await m.symmetricDecryptBytes(g, otherKey), fx.contents[2])
})

//############################################################
// KDF: PBKDF2-SHA256, 48 bytes
test(`KDF matches PBKDF2-SHA256 known answer`, async () => {
    const saltHex = "00112233445566778899aabbccddeeff"
    const expected = pbkdf2Sync("correct horse", Buffer.from(saltHex, "hex"), 1000, 48, "sha256").toString("hex")
    assert.deepEqual(await m.deriveSymKeyFromPassword("correct horse", saltHex, 1000), { keyHex: expected, saltHex, iterations: 1000 })
})

test(`KDF defaults: random 16 byte salt, 600000 iterations, key works`, async () => {
    const a = await m.deriveSymKeyFromPassword("pin1234")
    assert.equal(a.iterations, 600000)
    assert.match(a.saltHex, /^[0-9a-f]{32}$/)
    assert.match(a.keyHex, /^[0-9a-f]{96}$/)
    assert.notEqual(a.saltHex, (await m.deriveSymKeyFromPassword("pin1234", undefined, 1000)).saltHex)
    assert.equal((await m.deriveSymKeyFromPassword("pin1234", a.saltHex)).keyHex, a.keyHex)
    assert.equal(await m.symmetricDecryptHex(await m.symmetricEncryptHex("secret", a.keyHex), a.keyHex), "secret")
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
    for (const bad of ["abc", "zz".repeat(32), "0x" + "00".repeat(31), null, 42]) {
        await assert.rejects(async () => m.createPublicKeyHex(bad), SyntaxError, String(bad))
    }
    await assert.rejects(async () => m.symmetricDecryptHex("0g", symKeyHex), SyntaxError)
    await assert.rejects(async () => m.verifyHex("00", alice.publicKeyHex + "x", "c"), SyntaxError)
})

test(`symmetric keys shorter than 48 bytes are rejected`, async () => {
    for (const len of [0, 32, 40, 47]) {
        await assert.rejects(m.symmetricEncryptBytes("x", keyBytes.subarray(0, len)), RangeError, `len ${len}`)
        await assert.rejects(m.symmetricDecryptBytes(await encrypt("x"), keyBytes.subarray(0, len)), RangeError)
    }
    await assert.rejects(m.symmetricEncryptBytes("x", undefined), RangeError)
})

test(`ed25519 lengths are enforced (noble)`, async () => {
    await assert.rejects(m.createSignatureBytes("c", new Uint8Array(31)), RangeError)
    await assert.rejects(m.verifyBytes(new Uint8Array(63), hexToBytes(alice.publicKeyHex), "c"), RangeError)
    await assert.rejects(m.diffieHellmanSecretRawBytes(new Uint8Array(33), hexToBytes(bob.publicKeyHex)), RangeError)
})

test(`KDF rejects bad iterations and salt`, async () => {
    for (const it of [0, -1, 1.5, "1000"]) await assert.rejects(m.deriveSymKeyFromPassword("pw", "00".repeat(16), it), RangeError, String(it))
    await assert.rejects(m.deriveSymKeyFromPassword("pw", "xyz", 1000), SyntaxError)
})

test(`asymmetric v1 tamper is rejected`, async () => {
    const s = await m.asymmetricEncryptBytes(fx.contents[3], hexToBytes(bob.publicKeyHex))
    s.encryptedContentBytes[20] ^= 1
    await assert.rejects(m.asymmetricDecryptBytes(s, hexToBytes(bob.secretKeyHex)), /Decryption failed/)
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
    assert.equal(await m.symmetricDecryptBytes(await seal(new Uint8Array([2, 104, 105, 0, 0])), keyBytes), "hi")
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
        assert.equal(await m.verifyHex(smallOrder[0] + "00".repeat(32), p, "anything"), false, p)
        await assert.rejects(m.diffieHellmanSecretRawHex(bob.secretKeyHex, p), RangeError, p)
        await assert.rejects(m.diffieHellmanSecretHashHex(bob.secretKeyHex, p, "ctx"), RangeError)
        await assert.rejects(m.elGamalSecretRawHex(p), RangeError)
        await assert.rejects(m.elGamalSecretHashHex(p, "ctx"), RangeError)
        await assert.rejects(m.asymmetricEncryptHex("x", p), RangeError)
        const s = await m.asymmetricEncryptHex("x", bob.publicKeyHex)
        await assert.rejects(m.asymmetricDecryptHex({ ...s, referencePointHex: p }, bob.secretKeyHex), RangeError)
    }
})

test(`verify is strict: non-canonical encodings and malleable S rejected`, async () => {
    const s = fx.signatures[1]
    // identity with y = p + 1, only decodable in zip215 mode
    assert.equal(await m.verifyHex(smallOrder[0] + "00".repeat(32), "ee" + "ff".repeat(30) + "7f", "anything"), false)
    // S + L: same signature in a second encoding
    const L = 2n ** 252n + 27742317777372353535851937790883648493n
    const S = BigInt("0x" + Buffer.from(s.sigHex.slice(64), "hex").reverse().toString("hex"))
    const sPlusL = Buffer.from((S + L).toString(16).padStart(64, "0"), "hex").reverse().toString("hex")
    assert.equal(await m.verifyHex(s.sigHex.slice(0, 64) + sPlusL, alice.publicKeyHex, s.content), false)
})

test(`non-ASCII and large content roundtrip`, async () => {
    const contents = ["Grüße, Müßiggänger", "🔐🗝️👩‍👩‍👧", "秘密の鍵", "€".repeat(350000)]
    for (const c of contents) {
        assert.equal(await m.symmetricDecryptHex(await m.symmetricEncryptHex(c, symKeyHex), symKeyHex), c)
        assert.equal(await m.asymmetricDecryptHex(await m.asymmetricEncryptHex(c, bob.publicKeyHex), bob.secretKeyHex), c)
        assert.equal(await m.verifyHex(await m.createSignatureHex(c, alice.secretKeyHex), alice.publicKeyHex, c), true)
    }
})

test(`lone surrogates are rejected`, async () => {
    for (const bad of ["a\uD800b", "\uDC00", "x\uD83D"]) {
        await assert.rejects(m.symmetricEncryptHex(bad, symKeyHex), TypeError)
        await assert.rejects(m.asymmetricEncryptHex(bad, bob.publicKeyHex), TypeError)
        await assert.rejects(m.createSignatureHex(bad, alice.secretKeyHex), TypeError)
        await assert.rejects(m.verifyHex(fx.signatures[0].sigHex, alice.publicKeyHex, bad), TypeError)
        await assert.rejects(m.sha256Hex(bad), TypeError)
        await assert.rejects(m.diffieHellmanSecretHashHex(alice.secretKeyHex, bob.publicKeyHex, bad), TypeError)
        await assert.rejects(m.deriveSymKeyFromPassword(bad, "00".repeat(16), 1000), TypeError)
    }
    await assert.rejects(m.symmetricEncryptBytes(new Uint8Array([1, 2]), keyBytes), TypeError)
})

test(`KDF rejects salts shorter than 16 bytes`, async () => {
    for (const salt of ["", "00", "00".repeat(15)]) await assert.rejects(m.deriveSymKeyFromPassword("pw", salt, 1000), RangeError, salt)
})

test(`asymmetric referencePoint bit flips are rejected`, async () => {
    const s = await m.asymmetricEncryptBytes(fx.contents[3], hexToBytes(bob.publicKeyHex))
    for (let bit = 0; bit < 256; bit++) {
        const referencePointBytes = s.referencePointBytes.slice()
        referencePointBytes[bit >> 3] ^= 1 << (bit & 7)
        await assert.rejects(m.asymmetricDecryptBytes({ ...s, referencePointBytes }, hexToBytes(bob.secretKeyHex)), `bit ${bit}`)
    }
})

test(`uppercase hex is accepted`, async () => {
    const g = await m.symmetricEncryptHex("x", symKeyHex)
    assert.equal(await m.symmetricDecryptHex(g.toUpperCase(), symKeyHex.toUpperCase()), "x")
    assert.equal(await m.createPublicKeyHex(alice.secretKeyHex.toUpperCase()), alice.publicKeyHex)
    const s = fx.signatures[0]
    assert.equal(await m.verifyHex(s.sigHex.toUpperCase(), alice.publicKeyHex.toUpperCase(), s.content), true)
})

test(`every Hex function rejects invalid hex`, async () => {
    const bad = "zz".repeat(32)
    const calls = [
        () => m.createPublicKeyHex(bad),
        () => m.createSignatureHex("c", bad),
        () => m.verifyHex(bad, alice.publicKeyHex, "c"),
        () => m.verifyHex(fx.signatures[0].sigHex, bad, "c"),
        () => m.symmetricEncryptHex("c", bad + bad),
        () => m.symmetricDecryptHex(bad, symKeyHex),
        () => m.symmetricDecryptHex("00", bad + bad),
        () => m.asymmetricEncryptHex("c", bad),
        () => m.asymmetricDecryptHex({ referencePointHex: bad, encryptedContentHex: "00" }, bob.secretKeyHex),
        () => m.asymmetricDecryptHex({ referencePointHex: alice.publicKeyHex, encryptedContentHex: bad }, bob.secretKeyHex),
        () => m.asymmetricDecryptHex({ referencePointHex: alice.publicKeyHex, encryptedContentHex: "00" }, bad),
        () => m.diffieHellmanSecretRawHex(bad, bob.publicKeyHex),
        () => m.diffieHellmanSecretRawHex(alice.secretKeyHex, bad),
        () => m.diffieHellmanSecretHashHex(bad, bob.publicKeyHex),
        () => m.diffieHellmanSecretHashHex(alice.secretKeyHex, bad),
        () => m.elGamalSecretRawHex(bad),
        () => m.elGamalSecretHashHex(bad),
        () => m.deriveSymKeyFromPassword("pw", bad, 1000),
    ]
    for (const [i, call] of calls.entries()) await assert.rejects(async () => call(), SyntaxError, `call ${i}`)
})
