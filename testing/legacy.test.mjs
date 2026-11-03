// output/legacy.js reads the frozen fixtures of the published versions - spec: legacy-formats.md
import { test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"

const fixture = (name) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"))
const fx020 = fixture("v0.2.0.json")
const fx031 = fixture("v0.3.1.json")
const m = await import("../output/index.js")
const l = await import("../output/legacy.js")
const hexToBytes = (h) => new Uint8Array(Buffer.from(h, "hex"))
const bytesToHex = (b) => Buffer.from(b).toString("hex")

// every entry in hex and in bytes mode
const decryptsAll = async (entries, read) => {
    for (const e of entries) {
        assert.equal(await read(e, (h) => h), e.content, `${e.build}/${e.variant}`)
        assert.equal(await read(e, hexToBytes), e.content, `${e.build}/${e.variant} bytes`)
    }
}
const secrets = (e, as) => as == hexToBytes
    ? { referencePointBytes: hexToBytes(e.referencePointHex), encryptedContentBytes: hexToBytes(e.encryptedContentHex) }
    : { referencePointHex: e.referencePointHex, encryptedContentHex: e.encryptedContentHex }

test(`symmetric v0.2.0 and v0.3.1`, async () => {
    await decryptsAll(fx020.symmetric, (e, as) => l.symmetricDecryptV0_2_0(as(e.gibbrishHex), as(fx020.symKeyHex)))
    await decryptsAll(fx031.symmetric, (e, as) => l.symmetricDecryptV0_3_1(as(e.gibbrishHex), as(fx031.symKeyHex)))
})

test(`asymmetric v0.0.7, v0.2.0 and v0.3.1`, async () => {
    const bob020 = fx020.bob.secretKeyHex, bob031 = fx031.bob.secretKeyHex
    await decryptsAll(fx020.asymmetricOld, (e, as) => l.asymmetricDecryptV0_0_7(secrets(e, as), as(bob020)))
    await decryptsAll(fx020.asymmetric, (e, as) => l.asymmetricDecryptV0_2_0(secrets(e, as), as(bob020)))
    await decryptsAll(fx031.asymmetric, (e, as) => l.asymmetricDecryptV0_3_1(secrets(e, as), as(bob031)))
    // 0.0.x property names
    const e = fx020.asymmetricOld[2]
    assert.equal(await l.asymmetricDecryptV0_0_7({ referencePoint: e.referencePointHex, encryptedContent: e.encryptedContentHex }, bob020), e.content)
})

test(`signatures v0.2.0 verify, never throw`, async () => {
    const { alice, bob } = fx020
    for (const s of fx020.signatures) {
        assert.equal(await l.verifySignatureV0_2_0(s.sigHex, alice.publicKeyHex, s.content), undefined)
        assert.equal(await l.verifySignatureV0_2_0(hexToBytes(s.sigHex), hexToBytes(alice.publicKeyHex), s.content), undefined)
        assert.equal(await l.verifySignatureV0_2_0(s.sigHex, bob.publicKeyHex, s.content), "Invalid signature!")
        assert.equal(await l.verifySignatureV0_2_0(s.sigHex, alice.publicKeyHex, s.content + "!"), "Invalid signature!")
        // the main API signs the content itself, not its hash
        assert.equal(typeof await m.verifySignature(s.sigHex, alice.publicKeyHex, s.content), "string")
    }
    const s = fx020.signatures[0]
    for (const args of [["zz", alice.publicKeyHex, s.content], [s.sigHex, null, s.content], [s.sigHex, alice.publicKeyHex, 42], [s.sigHex, alice.publicKeyHex, "a\uD800"]]) {
        assert.equal(await l.verifySignatureV0_2_0(...args), "Malformed input!")
    }
    // small-order key with R = identity, S = 0
    assert.equal(typeof await l.verifySignatureV0_2_0("01" + "00".repeat(63), "01" + "00".repeat(31), "anything"), "string")
})

test(`hashed DH and elGamal v0.2.0, both sides agree`, async () => {
    const { alice, bob } = fx020
    for (const d of fx020.diffieHellman) {
        assert.equal(await l.diffieHellmanSecretHashV0_2_0(alice.secretKeyHex, bob.publicKeyHex, d.context), d.hashHex)
        assert.equal(await l.diffieHellmanSecretHashV0_2_0(bob.secretKeyHex, alice.publicKeyHex, d.context), d.hashHex)
        const hb = await l.diffieHellmanSecretHashV0_2_0(hexToBytes(alice.secretKeyHex), hexToBytes(bob.publicKeyHex), d.context)
        assert.equal(bytesToHex(hb), d.hashHex)
    }
    for (const e of fx020.elGamal.filter((e) => e.kind == "hash")) {
        assert.equal(await l.diffieHellmanSecretHashV0_2_0(bob.secretKeyHex, e.referencePointHex, e.context), e.sharedSecretHex, `${e.build}/${e.context}`)
    }
    await assert.rejects(l.diffieHellmanSecretHashV0_2_0(bob.secretKeyHex, "01" + "00".repeat(31)), RangeError)
})

test(`DH and elGamal v0.3.1, both sides agree`, async () => {
    const { alice, bob } = fx031
    for (const d of fx031.diffieHellman) {
        assert.equal(await l.diffieHellmanSecretRawV0_3_1(alice.secretKeyHex, bob.publicKeyHex), d.rawHex)
        assert.equal(await l.diffieHellmanSecretRawV0_3_1(bob.secretKeyHex, alice.publicKeyHex), d.rawHex)
        assert.equal(await l.diffieHellmanSecretHashV0_3_1(alice.secretKeyHex, bob.publicKeyHex, d.context), d.hashHex)
        const hb = await l.diffieHellmanSecretHashV0_3_1(hexToBytes(bob.secretKeyHex), alice.publicKeyHex, d.context)
        assert.equal(bytesToHex(hb), d.hashHex)
        // main is X25519 now
        assert.notEqual(await m.diffieHellmanSecretRaw(alice.secretKeyHex, bob.publicKeyHex), d.rawHex)
    }
    for (const e of fx031.elGamal) {
        const recovered = e.kind == "hash"
            ? await l.diffieHellmanSecretHashV0_3_1(bob.secretKeyHex, e.referencePointHex, e.context)
            : await l.diffieHellmanSecretRawV0_3_1(bob.secretKeyHex, e.referencePointHex)
        assert.equal(recovered, e.sharedSecretHex, `${e.build}/${e.kind}/${e.context}`)
    }
    await assert.rejects(l.diffieHellmanSecretRawV0_3_1(bob.secretKeyHex, "01" + "00".repeat(31)), RangeError)
})

// X2: no legacy fixture gets through the main API, including CBC ciphertexts starting with 0x01
test(`main decrypt rejects every legacy fixture`, async () => {
    const prefixed = fx031.symmetric.filter((s) => s.gibbrishHex.startsWith("01"))
    assert.ok(prefixed.length > 0)
    for (const [fx, e] of [...fx020.symmetric.map((e) => [fx020, e]), ...fx031.symmetric.map((e) => [fx031, e])]) {
        await assert.rejects(m.symmetricDecrypt(e.gibbrishHex, fx.symKeyHex), /Decryption failed/)
    }
    for (const [fx, e] of [...fx020.asymmetric, ...fx020.asymmetricOld].map((e) => [fx020, e]).concat(fx031.asymmetric.map((e) => [fx031, e]))) {
        await assert.rejects(m.asymmetricDecrypt(secrets(e, (h) => h), fx.bob.secretKeyHex), /Decryption failed/)
    }
})

test(`a legacy function rejects the other groups' data`, async () => {
    // salt envelope or padding fails loudly - V0_2_0 symmetric has no integrity check, so only check what may throw
    const e031 = fx031.symmetric[2]
    await assert.rejects(l.symmetricDecryptV0_3_1(fx020.symmetric[2].gibbrishHex, fx020.symKeyHex))
    await assert.rejects(l.asymmetricDecryptV0_3_1(secrets(fx020.asymmetric[2], (h) => h), fx020.bob.secretKeyHex))
    await assert.rejects(l.asymmetricDecryptV0_2_0(secrets(fx031.asymmetric[4], (h) => h), fx031.bob.secretKeyHex))
    await assert.rejects(l.symmetricDecryptV0_3_1(e031.gibbrishHex, "00".repeat(48)))
})

test(`legacy entry point exports exactly the spec'd functions`, () => {
    assert.deepEqual(Object.keys(l).sort(), [
        "asymmetricDecryptV0_0_7", "asymmetricDecryptV0_2_0", "asymmetricDecryptV0_3_1",
        "diffieHellmanSecretHashV0_2_0", "diffieHellmanSecretHashV0_3_1", "diffieHellmanSecretRawV0_3_1",
        "symmetricDecryptV0_2_0", "symmetricDecryptV0_3_1", "verifySignatureV0_2_0",
    ])
})

// no equalizing in legacy: noble's Error for a point not on the curve, RangeError for non-canonical and small-order
test(`legacy functions reject invalid points and incomplete secrets`, async () => {
    const { bob } = fx031
    const e = fx031.asymmetric[0]
    for (const p of ["02" + "00".repeat(31), "ed" + "ff".repeat(30) + "7f", "01" + "00".repeat(31), "00".repeat(31)]) {
        await assert.rejects(l.diffieHellmanSecretRawV0_3_1(bob.secretKeyHex, p), Error, p)
        await assert.rejects(l.diffieHellmanSecretHashV0_3_1(bob.secretKeyHex, p), Error, p)
        await assert.rejects(l.diffieHellmanSecretHashV0_2_0(bob.secretKeyHex, p), Error, p)
        for (const read of [l.asymmetricDecryptV0_0_7, l.asymmetricDecryptV0_2_0, l.asymmetricDecryptV0_3_1]) {
            await assert.rejects(read({ referencePointHex: p, encryptedContentHex: e.encryptedContentHex }, bob.secretKeyHex), Error, `${read.name} ${p}`)
        }
    }
    for (const read of [l.asymmetricDecryptV0_0_7, l.asymmetricDecryptV0_2_0, l.asymmetricDecryptV0_3_1]) {
        for (const bad of [{}, { referencePointHex: e.referencePointHex }, { encryptedContentHex: e.encryptedContentHex }]) {
            await assert.rejects(read(bad, bob.secretKeyHex), /Invalid secrets Object/, read.name)
        }
        await assert.rejects(read(null, bob.secretKeyHex), TypeError, read.name)
    }
})

test(`every legacy rejection is an Error`, async () => {
    const bad = [undefined, null, 42, "", "zz", {}, new Uint8Array(0), new Uint8Array(64), "a\uD800"]
    for (const [name, fn] of Object.entries(l)) {
        for (const x of bad) await fn(x, x, x).then(() => {}, (e) => assert.ok(e instanceof Error, `${name}(${String(x)}): ${e}`))
    }
})

// lenient: any byte flavor reads old data, copied to plain memory before WebCrypto sees it
test(`legacy functions take any byte flavor`, async () => {
    const e = fx031.symmetric[2]
    const copyInto = (buffer, b) => { new Uint8Array(buffer).set(b); return buffer }
    const flavors = {
        arrayBuffer: (b) => b.slice().buffer,
        dataView: (b) => new DataView(b.slice().buffer),
        resizable: (b) => new Uint8Array(copyInto(new ArrayBuffer(b.length, { maxByteLength: 1024 }), b)),
    }
    if (typeof SharedArrayBuffer == "function") flavors.shared = (b) => new Uint8Array(copyInto(new SharedArrayBuffer(b.length), b))
    for (const [name, f] of Object.entries(flavors)) {
        assert.equal(await l.symmetricDecryptV0_3_1(f(hexToBytes(e.gibbrishHex)), f(hexToBytes(fx031.symKeyHex))), e.content, name)
    }
})
