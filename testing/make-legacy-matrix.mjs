// One-shot: cross-version compatibility matrix of all *published* versions (+ current output/ as consumer).
// usage: for v in 0.0.1 ... 0.3.1; do npm i --prefix <dir>/v$v secret-manager-crypto-utils@$v; done
//        node testing/make-legacy-matrix.mjs <dir>
// Every producer (version × node/browser build) encrypts/signs/derives, every consumer decrypts/verifies/recomputes.
// Prints one markdown table per operation: "ok" | "wrong" (no error, wrong result) | "err" (throws) | "-" (missing).
import fs from "node:fs"
import path from "node:path"
import { createRequire } from "node:module"

const root = path.resolve(process.argv[2])
globalThis.window ??= globalThis // browser builds read window.crypto
const hex = (b) => Buffer.from(b).toString("hex")
const cmp = (a, b) => a.localeCompare(b, undefined, { numeric: true })
const versions = fs.readdirSync(root).filter((d) => d.startsWith("v")).map((d) => d.slice(1)).sort(cmp)

const load = async (file) => {
    if (!fs.existsSync(file)) return null
    try { return file.endsWith(".js") && fs.readFileSync(file, "utf8").includes("\nimport ") ? await import(file) : createRequire(file)(file) }
    catch (e) { return { loadError: e.message } }
}
const builds = [] // { name, m }
for (const v of versions) {
    const dir = path.join(root, "v" + v, "node_modules", "secret-manager-crypto-utils")
    const node = await load(path.join(dir, "cryptoutilsnode.js")) ?? await load(path.join(dir, "node.js")) ?? await load(path.join(dir, "index.js"))
    const browser = await load(path.join(dir, "cryptoutilsbrowser.js")) ?? await load(path.join(dir, "browser.js"))
    builds.push({ name: v + "n", m: node }, { name: v + "b", m: browser })
}
const current = { name: "cur", m: await import(path.resolve(import.meta.dirname, "../output/index.js")) }

// Normalize the API over all versions. m[fn](...) keeps `this` for 0.0.x which calls this.sha512Hex etc.
const call = (m, names, ...args) => { const n = names.find((n) => typeof m?.[n] === "function"); return n ? m[n](...args) : undefined }
const has = (m, names) => names.some((n) => typeof m?.[n] === "function")
const ops = {
    symEnc: ["symmetricEncryptHex", "symetricEncryptHex"], symDec: ["symmetricDecryptHex", "symetricDecryptHex"],
    asymEnc: ["asymmetricEncryptHex", "asymetricEncrypt"], asymDec: ["asymmetricDecryptHex", "asymetricDecrypt"],
    sign: ["createSignatureHex", "createSignature"], verify: ["verifySignatureHex", "verifyHex", "verify"],
    dhRaw: ["diffieHellmanSecretRawHex", "createSharedSecretRawHex", "createSharedSecretRaw"],
    dhHash: ["diffieHellmanSecretHashHex", "createSharedSecretHashHex", "createSharedSecretHash"],
    egRaw: ["elGamalSecretRawHex", "referencedSharedSecretRawHex", "referencedSharedSecretRaw"],
    egHash: ["elGamalSecretHashHex", "referencedSharedSecretHashHex", "referencedSharedSecretHash"]
}

// Fixed inputs. Public keys are identical in every noble version (checked separately), so derive them with current.
const aliceSk = hex(new Uint8Array(32).map((_, i) => i + 1)), bobSk = hex(new Uint8Array(32).map((_, i) => i + 33))
const alicePk = await current.m.createPublicKeyHex(aliceSk), bobPk = await current.m.createPublicKeyHex(bobSk)
const symKey = hex(new Uint8Array(48).map((_, i) => i + 65))
const contents = ["", "a", "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^", "x".repeat(1000)]
const contexts = ["", "some-context"]

const tryIt = async (f) => { try { return { v: await f() } } catch (e) { return { e: e.message } } }
const consumers = [...builds, current]
const tables = {}
const cell = (table, prod, cons, res) => ((tables[table] ??= {})[prod] ??= {})[cons] = res
const merge = (a, b) => a === undefined ? b : a === b ? a : a === "-" ? b : b === "-" ? a : a === "err" || b === "err" ? "err" : "wrong"

// producers: every build, plus asymmetricEncryptOld of 0.1.x/0.2.0 as its own row
const producers = [...builds, current]
for (const b of builds) if (has(b.m, ["asymmetricEncryptOld"])) producers.push({ name: b.name + "-old", m: b.m, old: true })

for (const p of producers) {
    for (const content of contents) {
        // symmetric
        if (!p.old) {
            const enc = await tryIt(() => call(p.m, ops.symEnc, content, symKey))
            for (const c of consumers) {
                let r = "-"
                if (enc.e) r = "enc-err"
                else if (enc.v !== undefined && has(c.m, ops.symDec)) { const d = await tryIt(() => call(c.m, ops.symDec, enc.v, symKey)); r = d.e ? "err" : d.v === content ? "ok" : "wrong" }
                cell("symmetric", p.name, c.name, merge(tables.symmetric?.[p.name]?.[c.name], r))
            }
        }
        // asymmetric
        const enc = await tryIt(() => p.old ? p.m.asymmetricEncryptOld(content, bobPk) : call(p.m, ops.asymEnc, content, bobPk))
        const secrets = enc.v && { referencePoint: enc.v.referencePointHex ?? enc.v.referencePoint, encryptedContent: enc.v.encryptedContentHex ?? enc.v.encryptedContent }
        if (secrets) Object.assign(secrets, { referencePointHex: secrets.referencePoint, encryptedContentHex: secrets.encryptedContent })
        for (const c of consumers) {
            let r = "-"
            if (enc.e) r = "enc-err"
            else if (secrets && has(c.m, ops.asymDec)) { const d = await tryIt(() => call(c.m, ops.asymDec, secrets, bobSk)); r = d.e ? "err" : d.v === content ? "ok" : "wrong" }
            cell("asymmetric", p.name, c.name, merge(tables.asymmetric?.[p.name]?.[c.name], r))
        }
        if (p.old) continue
        // signatures
        const sig = await tryIt(() => call(p.m, ops.sign, content, aliceSk))
        for (const c of consumers) {
            let r = "-"
            if (sig.e) r = "sign-err"
            else if (sig.v !== undefined && has(c.m, ops.verify)) {
                const d = await tryIt(() => call(c.m, ops.verify, typeof sig.v === "string" ? sig.v : hex(sig.v), alicePk, content))
                r = d.e ? "err" : (d.v === true || (c === current && d.v === undefined)) ? "ok" : "wrong"
            }
            cell("signatures", p.name, c.name, merge(tables.signatures?.[p.name]?.[c.name], r))
        }
    }
    if (p.old) continue
    // DH: value comparison (raw + hash per context); elGamal: consumer recomputes via its DH with bob's secret key
    for (const c of consumers) {
        let r
        for (const ctx of [null, ...contexts]) {
            const f = (m) => tryIt(async () => { const v = ctx === null ? await call(m, ops.dhRaw, aliceSk, bobPk) : await call(m, ops.dhHash, aliceSk, bobPk, ctx); return v === undefined ? undefined : hex(Buffer.from(v, "hex")) })
            const [a, b] = [await f(p.m), await f(c.m)]
            r = merge(r, a.e || b.e ? "err" : a.v === undefined || b.v === undefined ? "-" : a.v === b.v ? "ok" : "wrong")
        }
        cell("diffieHellman", p.name, c.name, r)
        r = undefined
        for (const ctx of [null, ...contexts]) {
            const eg = await tryIt(() => ctx === null ? call(p.m, ops.egRaw, bobPk) : call(p.m, ops.egHash, bobPk, ctx))
            if (eg.e) { r = merge(r, "enc-err"); continue }
            if (eg.v === undefined) { r = merge(r, "-"); continue }
            const d = await tryIt(() => ctx === null ? call(c.m, ops.dhRaw, bobSk, eg.v.referencePointHex) : call(c.m, ops.dhHash, bobSk, eg.v.referencePointHex, ctx))
            r = merge(r, d.e ? "err" : d.v === undefined ? "-" : d.v === eg.v.sharedSecretHex ? "ok" : "wrong")
        }
        cell("elGamal", p.name, c.name, r)
    }
}

const abbrev = { ok: "✓", wrong: "✗", err: "E", "enc-err": "P", "sign-err": "P", "-": "·" }
for (const [name, t] of Object.entries(tables)) {
    const cols = consumers.map((c) => c.name)
    console.log(`\n### ${name}  (rows produce, columns consume — ✓ ok · ✗ wrong result · E consumer throws · P producer throws · · missing)\n`)
    console.log("| producer | " + cols.join(" | ") + " |")
    console.log("|---|" + cols.map(() => "---").join("|") + "|")
    for (const [prod, row] of Object.entries(t)) if (Object.values(row).some((x) => x !== "-")) console.log(`| ${prod} | ` + cols.map((c) => abbrev[row[c]] ?? "?").join(" | ") + " |")
}
const broken = builds.filter((b) => !b.m || b.m.loadError)
if (broken.length) console.log("\nload errors:\n" + broken.map((b) => `- ${b.name}: ${b.m?.loadError ?? "no file"}`).join("\n"))
