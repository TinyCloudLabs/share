import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";

const definition = `flowchart TD
  A([Agent writes app.jsx]) --> B[tc share publish]
  B --> C{{Link with a key}}
  C --> D[Recipient opens link]
  D --> E[Sandboxed frame runs it]
  E --> F([Revoke any time])`;

// mermaid is bundled and themed from the TinyCloud tokens; it never touches the network.
export default function Diagram() {
  const host = useRef(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    mermaid
      .render("flow", definition)
      .then(({ svg }) => {
        if (!cancelled && host.current) host.current.innerHTML = svg;
      })
      .catch((reason) => setError(String(reason)));
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="min-h-screen p-6 bg-tc-page text-tc-text">
      <section className="mx-auto max-w-3xl rounded-tc-lg border border-tc-border bg-tc-surface p-6">
        <h1 className="text-xl font-semibold tracking-tight">How a share travels</h1>
        <p className="mb-4 text-sm text-tc-muted">Rendered by mermaid inside the sandbox.</p>
        {error ? <pre className="text-tc-danger">{error}</pre> : null}
        <div ref={host} data-testid="diagram" className="overflow-x-auto [&_svg]:mx-auto [&_svg]:max-w-full [&_svg]:h-auto" />
      </section>
    </main>
  );
}
