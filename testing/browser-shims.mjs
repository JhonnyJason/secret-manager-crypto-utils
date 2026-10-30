// Just enough of node:test, node:assert/strict, node:fs and Buffer to run the test files unchanged in a browser.
// One default export serves as both `assert` and `fs` (see the import map in browser.html).
export const tests = []
export const test = (name, fn) => { tests.push({ name, fn }) }

const fail = (msg) => { throw new Error(msg) }
const assert = {
    ok: (v, msg) => v || fail(msg ?? `not ok: ${v}`),
    equal: (a, b, msg) => Object.is(a, b) || fail(msg ?? `${a} !== ${b}`),
    match: (s, re, msg) => re.test(s) || fail(msg ?? `${s} does not match ${re}`),
    notEqual: (a, b, msg) => !Object.is(a, b) || fail(msg ?? `${a} === ${b}`),
    deepEqual: (a, b, msg) => JSON.stringify(a) == JSON.stringify(b) || fail(msg ?? `${JSON.stringify(a)} not deep-equal ${JSON.stringify(b)}`),
    rejects: async (p, matcher, msg) => {
        try { await (typeof p == "function" ? p() : p) } catch (e) {
            if (matcher instanceof RegExp && !matcher.test(e?.message)) fail(msg ?? `rejected with "${e?.message}", expected ${matcher}`)
            if (typeof matcher == "function" && !(e instanceof matcher)) fail(msg ?? `rejected with ${e?.name}, expected ${matcher.name}`)
            return
        }
        fail(msg ?? "did not reject")
    },
    // fs: synchronous XHR, the test files read their fixtures at load
    readFileSync: (url) => {
        const xhr = new XMLHttpRequest()
        xhr.open("GET", String(url), false)
        xhr.send()
        if (xhr.status != 200) fail(`GET ${url}: ${xhr.status}`)
        return xhr.responseText
    },
}
export default assert

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
globalThis.Buffer = {
    from: (v, enc) => {
        const bytes = enc == "hex" ? Uint8Array.from(v.match(/../g) ?? [], (h) => parseInt(h, 16)) : Uint8Array.from(v)
        bytes.toString = (e) => e == "hex" ? hex(bytes) : fail("Buffer shim: hex only")
        return bytes
    },
}
