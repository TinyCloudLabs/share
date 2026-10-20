// Benign sandbox self-check. Each probe is something an artifact must NOT be
// able to do. It tries the operation, catches, and records the outcome as text
// in the page; the e2e test reads the DOM and asserts every probe failed.
import { useEffect, useState } from "react";

const BEACON = "__BEACON__";

async function attempt(run) {
  try {
    const value = await run();
    return { ok: true, value: String(value) };
  } catch (error) {
    return { ok: false, name: error && error.name ? error.name : "Error" };
  }
}

export default function SelfCheck() {
  const [report, setReport] = useState(null);

  useEffect(() => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      violations.push(event.violatedDirective);
    });
    (async () => {
      const result = {};
      result.parentDocument = await attempt(() => window.parent.document.body);
      result.topDocument = await attempt(() => window.top.document.body);
      result.localStorage = await attempt(() => window.localStorage.getItem("probe"));
      result.sessionStorage = await attempt(() => window.sessionStorage.getItem("probe"));
      result.indexedDB = await attempt(
        () => new Promise((resolve, reject) => {
          const request = window.indexedDB.open("probe");
          request.onsuccess = () => resolve("opened");
          request.onerror = () => reject(request.error || new Error("error"));
        }),
      );
      result.cookie = await attempt(() => document.cookie);
      result.fetchRemote = await attempt(() => fetch(`${BEACON}/fetch`));
      result.fetchSameOrigin = await attempt(() => fetch("/"));
      result.worker = await attempt(
        () => new Promise((resolve, reject) => {
          const worker = new Worker(URL.createObjectURL(new Blob(["postMessage(1)"])));
          worker.onmessage = () => resolve("worker ran");
          worker.onerror = () => reject(new Error("worker error"));
          setTimeout(() => reject(new Error("worker timeout")), 1500);
        }),
      );
      result.windowOpen = await attempt(() => window.open(`${BEACON}/open`));
      result.topNavigation = await attempt(() => {
        window.top.location.href = `${BEACON}/top`;
        return "assigned";
      });
      result.origin = { ok: true, value: String(self.origin) };
      await new Promise((resolve) => setTimeout(resolve, 300));
      setReport({ result, violations: [...new Set(violations)] });
    })();
  }, []);

  return (
    <main className="p-6">
      <h1 className="text-lg font-semibold">Sandbox self-check</h1>
      <pre id="report" data-done={report ? "yes" : "no"} className="mt-3 text-xs whitespace-pre-wrap">
        {report ? JSON.stringify(report, null, 2) : "running"}
      </pre>
    </main>
  );
}
