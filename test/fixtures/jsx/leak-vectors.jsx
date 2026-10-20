// The leak-vector probe as a shared page: every browser-initiated request the frame's CSP does not govern, tried
// through React elements and through the DOM. test/e2e-jsx.mjs asserts a loopback listener sees nothing at all
// (the `navigation` mode, which still opens a connection, is run apart and reported as a known limit).
import { createElement, useEffect, useState } from "react";

const BEACON = "__BEACON__";
const MODE = "__PROBES__";
/*__LEAK_VECTORS__*/

export default function LeakVectors() {
  const [report, setReport] = useState(null);
  useEffect(() => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.violatedDirective));
    runLeakVectors(BEACON, "secret-marker-9f31", { navigation: MODE === "navigation", only: MODE.startsWith("only:") ? MODE.slice(5) : "" }).then((outcomes) => setReport({ outcomes, violations: [...new Set(violations)] }));
  }, []);
  // Declarative: the elements an app would write in JSX.
  const declared = MODE === "navigation" || MODE.startsWith("only:") ? [] : leakJsxVectors(BEACON, "secret-marker-9f31").map(([tag, props], index) => createElement(tag, { key: index, ...props }));
  return (
    <main>
      <div id="declared">{declared}</div>
      <pre id="report" data-done={report ? "yes" : "no"}>{report ? JSON.stringify(report) : "running"}</pre>
    </main>
  );
}
