#!/usr/bin/env node
// Runs a test file in every installed headless browser: node testing/browser.mjs [legacy.test.mjs] [browser...]
// Serves the repo root, each browser opens testing/browser.html and POSTs its results back.
import http from "node:http"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { spawn, spawnSync } from "node:child_process"

const root = path.resolve(import.meta.dirname, "..")
const file = process.argv[2] ?? "legacy.test.mjs"
const wanted = process.argv.slice(3)
const types = { ".html": "text/html", ".mjs": "text/javascript", ".js": "text/javascript", ".json": "application/json" }
const launchers = {
    chromium: (url, dir) => ["chromium", ["--headless=new", "--no-first-run", "--password-store=basic", `--user-data-dir=${dir}`, url]],
    "google-chrome-stable": (url, dir) => ["google-chrome-stable", ["--headless=new", "--no-first-run", "--password-store=basic", `--user-data-dir=${dir}`, url]],
    firefox: (url, dir) => ["firefox", ["--headless", "--no-remote", "--profile", dir, url]],
    // WebKit = Safari's engine; MiniBrowser has no headless mode, so it gets a virtual X display
    webkit: (url) => ["xvfb-run", ["-a", "/usr/lib/webkitgtk-6.0/MiniBrowser", "--private", url]],
}
const installed = { webkit: "/usr/lib/webkitgtk-6.0/MiniBrowser" }
const browsers = Object.keys(launchers).filter((b) => (wanted.length == 0 || wanted.includes(b)) && spawnSync("which", [installed[b] ?? b]).status == 0 && (b != "webkit" || spawnSync("which", ["xvfb-run"]).status == 0))

let pending
const server = http.createServer((req, res) => {
    if (req.method == "POST" && req.url == "/result") {
        let body = ""
        req.on("data", (c) => body += c).on("end", () => { res.end(); pending?.(JSON.parse(body)) })
        return
    }
    const p = path.join(root, decodeURIComponent(new URL(req.url, "http://x").pathname))
    if (!p.startsWith(root + path.sep)) return res.writeHead(403).end()
    fs.readFile(p, (err, data) => {
        if (err) return res.writeHead(404).end()
        res.writeHead(200, { "content-type": types[path.extname(p)] ?? "application/octet-stream" }).end(data)
    })
})
await new Promise((r) => server.listen(0, "127.0.0.1", r))
const url = `http://127.0.0.1:${server.address().port}/testing/browser.html?file=${encodeURIComponent(file)}`

let failed = browsers.length == 0
for (const b of browsers) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "browsertest-"))
    const [cmd, args] = launchers[b](url, dir)
    const proc = spawn(cmd, args, { stdio: "ignore", detached: true })
    const report = await Promise.race([
        new Promise((r) => pending = r),
        new Promise((r) => setTimeout(() => r(null), 60000)),
    ])
    process.kill(-proc.pid) // the whole group: xvfb-run leaves Xvfb and MiniBrowser behind otherwise
    await new Promise((r) => proc.exitCode != null || proc.signalCode ? r() : proc.on("exit", r))
    fs.rmSync(dir, { recursive: true, force: true })
    if (!report) { console.log(`✗ ${b}: no result within 60s`); failed = true; continue }
    const bad = report.results.filter((t) => !t.ok)
    console.log(`${bad.length ? "✗" : "✔"} ${b} - ${report.results.length - bad.length}/${report.results.length} - ${report.userAgent}`)
    for (const t of bad) console.log(`  ✗ ${t.name}\n    ${t.error.replaceAll("\n", "\n    ")}`)
    if (bad.length || report.results.length == 0) failed = true
}
server.close()
process.exit(failed ? 1 : 0)
