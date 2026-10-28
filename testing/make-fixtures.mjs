// One-shot: freezes outputs of a *published* version into fixtures/v<version>.json.
// usage: node testing/make-fixtures.mjs <dir of installed secret-manager-crypto-utils>
// e.g.:  npm i --prefix /tmp/v031 secret-manager-crypto-utils@0.3.1
//        node testing/make-fixtures.mjs /tmp/v031/node_modules/secret-manager-crypto-utils
import fs from "node:fs"
import path from "node:path"

const pkgDir = path.resolve(process.argv[2])
const { version } = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"))
globalThis.window ??= globalThis // the browser build reads window.crypto
const builds = {
    node: await import(path.join(pkgDir, "index.js")),
    browser: await import(path.join(pkgDir, "browser.js"))
}
const hex = (b) => Buffer.from(b).toString("hex")
const contents = [
    "",
    "a",
    "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^",
    JSON.stringify({ gh: { accessToken: "ghp_0123456789abcdef", host: "github.com" } }),
    "x".repeat(1000)
]
const contexts = ["", "some-context"]

const n = builds.node
const alice = await n.createKeyPairHex()
const bob = await n.createKeyPairHex()
const symKeyHex = await n.createSymKeyHex()

const f = { version, alice, bob, symKeyHex, contents, sha: [], signatures: [], symmetric: [], asymmetric: [], diffieHellman: [], elGamal: [], asymmetricOld: [] }

for (const c of contents) {
    f.sha.push({ content: c, sha256Hex: await n.sha256Hex(c), sha512Hex: await n.sha512Hex(c) })
    f.signatures.push({ content: c, sigHex: await n.createSignatureHex(c, alice.secretKeyHex) })
}

for (const [build, m] of Object.entries(builds)) {
    for (const c of contents) {
        f.symmetric.push({ build, variant: "hex", content: c, gibbrishHex: await m.symmetricEncryptHex(c, symKeyHex) })
        f.symmetric.push({ build, variant: "bytes", content: c, gibbrishHex: hex(await m.symmetricEncryptBytes(c, new Uint8Array(Buffer.from(symKeyHex, "hex")))) })

        const s = await m.asymmetricEncryptHex(c, bob.publicKeyHex)
        f.asymmetric.push({ build, variant: "hex", content: c, referencePointHex: s.referencePointHex, encryptedContentHex: s.encryptedContentHex })
        const sb = await m.asymmetricEncryptBytes(c, new Uint8Array(Buffer.from(bob.publicKeyHex, "hex")))
        f.asymmetric.push({ build, variant: "bytes", content: c, referencePointHex: hex(sb.referencePointBytes), encryptedContentHex: hex(sb.encryptedContentBytes) })
    }
    // legacy ciphertext starting with 0x01 (~1/256): main (v1) decrypt must reject it, a legacy decrypt must read it
    for (let i = 0; i < 100000; i++) {
        const gibbrishHex = await m.symmetricEncryptHex(contents[2], symKeyHex)
        if (gibbrishHex.startsWith("01")) { f.symmetric.push({ build, variant: "hex", content: contents[2], gibbrishHex }); break }
    }
    // 0.2.0 names: createSharedSecret* / referencedSharedSecret*
    const dhHash = m.diffieHellmanSecretHashHex ?? m.createSharedSecretHashHex, dhRaw = m.diffieHellmanSecretRawHex ?? m.createSharedSecretRawHex
    const egHash = m.elGamalSecretHashHex ?? m.referencedSharedSecretHashHex, egRaw = m.elGamalSecretRawHex ?? m.referencedSharedSecretRawHex
    for (const context of contexts) {
        f.diffieHellman.push({ build, context,
            hashHex: await dhHash(alice.secretKeyHex, bob.publicKeyHex, context),
            rawHex: await dhRaw(alice.secretKeyHex, bob.publicKeyHex) })
        // receiver recomputes sharedSecretHex via diffieHellmanSecretHash(bob.secretKeyHex, referencePointHex, context)
        f.elGamal.push({ build, context, kind: "hash", ...await egHash(bob.publicKeyHex, context) })
    }
    f.elGamal.push({ build, context: "", kind: "raw", ...await egRaw(bob.publicKeyHex) })
    // 0.1.0-0.2.0: asymmetricEncryptOld writes the 0.0.x asymmetric format
    if (m.asymmetricEncryptOld) for (const c of contents) {
        const s = await m.asymmetricEncryptOld(c, bob.publicKeyHex)
        f.asymmetricOld.push({ build, variant: "hex", content: c, referencePointHex: s.referencePointHex, encryptedContentHex: s.encryptedContentHex })
    }
}

if (!f.asymmetricOld.length) delete f.asymmetricOld

const out = path.join(import.meta.dirname, "fixtures", `v${version}.json`)
fs.mkdirSync(path.dirname(out), { recursive: true })
fs.writeFileSync(out, JSON.stringify(f, null, 2) + "\n")
console.log("wrote " + out)
