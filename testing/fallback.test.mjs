// runs test.mjs again with native Ed25519/X25519 hidden, so the noble fallback must pass the same tests
const subtle = globalThis.crypto.subtle
const importKey = subtle.importKey
let hidden = 0
subtle.importKey = function (format, keyData, algorithm, ...rest) {
    const name = algorithm?.name ?? algorithm
    if (name == "Ed25519" || name == "X25519") {
        hidden++
        return Promise.reject(new DOMException("hidden for the fallback test", "NotSupportedError"))
    }
    return importKey.call(this, format, keyData, algorithm, ...rest)
}
globalThis.moduleSuffix = "?fallback"
await import("../output/index.js?fallback")
subtle.importKey = importKey
if (hidden != 2) throw new Error(`expected the 2 native detections to be hidden, got ${hidden}`)
await import("./test.mjs?fallback")
