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

const f = { version, alice, bob, symKeyHex, contents, sha: [], signatures: [], symmetric: [], asymmetric: [], diffieHellman: [], elGamal: [] }

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
    // legacy ciphertext starting with 0x01 (~1/256): decrypt must fall back to CBC when the v1 tag fails
    for (let i = 0; i < 100000; i++) {
        const gibbrishHex = await m.symmetricEncryptHex(contents[2], symKeyHex)
        if (gibbrishHex.startsWith("01")) { f.symmetric.push({ build, variant: "hex", content: contents[2], gibbrishHex }); break }
    }
    for (const context of contexts) {
        f.diffieHellman.push({ build, context,
            hashHex: await m.diffieHellmanSecretHashHex(alice.secretKeyHex, bob.publicKeyHex, context),
            rawHex: await m.diffieHellmanSecretRawHex(alice.secretKeyHex, bob.publicKeyHex) })
        // receiver recomputes sharedSecretHex via diffieHellmanSecretHash(bob.secretKeyHex, referencePointHex, context)
        f.elGamal.push({ build, context, kind: "hash", ...await m.elGamalSecretHashHex(bob.publicKeyHex, context) })
    }
    f.elGamal.push({ build, context: "", kind: "raw", ...await m.elGamalSecretRawHex(bob.publicKeyHex) })
}

const out = path.join(import.meta.dirname, "fixtures", `v${version}.json`)
fs.mkdirSync(path.dirname(out), { recursive: true })
fs.writeFileSync(out, JSON.stringify(f, null, 2) + "\n")
console.log("wrote " + out)
