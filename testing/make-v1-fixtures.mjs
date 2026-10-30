// One-shot: freezes v1 output of the final v0.4.0 build into fixtures/v0.4.0.json - never regenerate, it is the v1 contract.
// usage: node testing/make-v1-fixtures.mjs
import fs from "node:fs"
import path from "node:path"

const m = await import("../output/index.js")
const { version } = JSON.parse(fs.readFileSync(new URL("../output/package.json", import.meta.url), "utf8"))
const out = path.join(import.meta.dirname, "fixtures", `v${version}.json`)
if (fs.existsSync(out)) throw new Error(`${out} exists - the frozen contract is never regenerated`)

const contents = [
    "",
    "a",
    "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^",
    JSON.stringify({ gh: { accessToken: "ghp_0123456789abcdef", host: "github.com" } }),
    "x".repeat(1000)
]
const contexts = ["", "some-context"]
const bob = await m.createKeyPair()
const symKeyHex = await m.createSymKey()

const f = { version, bob, symKeyHex, contents, symmetric: [], asymmetric: [] }
for (const context of contexts) for (const content of contents) {
    f.symmetric.push({ context, content, gibbrishHex: await m.symmetricEncrypt(content, symKeyHex, context) })
    f.asymmetric.push({ context, content, ...await m.asymmetricEncrypt(content, bob.publicKeyHex, context) })
}

fs.writeFileSync(out, JSON.stringify(f, null, 2) + "\n")
console.log("wrote " + out)
