import { useState } from "react";
import { Minus, Plus, RotateCcw } from "lucide-react";

// A small stateful app: React state, lucide icons and Tailwind classes that
// follow the TinyCloud tokens (bg-tc-*, text-tc-*, border-tc-*, rounded-tc-*).
export default function Counter() {
  const [count, setCount] = useState(0);
  const step = (delta) => setCount((value) => Math.max(0, value + delta));

  return (
    <main className="min-h-screen grid place-items-center p-6 bg-tc-page text-tc-text">
      <section className="w-full max-w-sm rounded-tc-lg border border-tc-border bg-tc-surface p-8 text-center">
        <p className="text-sm font-medium tracking-wide uppercase text-tc-muted">Counter</p>
        <output
          aria-live="polite"
          data-testid="count"
          className="block my-4 text-7xl font-semibold tabular-nums tracking-tight"
        >
          {count}
        </output>
        <div className="flex items-center justify-center gap-3">
          <button
            type="button"
            aria-label="Decrease"
            onClick={() => step(-1)}
            className="size-11 grid place-items-center rounded-full border border-tc-border bg-tc-subtle hover:border-tc-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tc-accent"
          >
            <Minus size={18} />
          </button>
          <button
            type="button"
            data-testid="increment"
            aria-label="Increase"
            onClick={() => step(1)}
            className="h-11 px-6 inline-flex items-center gap-2 rounded-full bg-tc-accent text-tc-on-accent font-medium hover:bg-tc-accent-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tc-accent"
          >
            <Plus size={18} /> Add one
          </button>
          <button
            type="button"
            aria-label="Reset"
            onClick={() => setCount(0)}
            className="size-11 grid place-items-center rounded-full border border-tc-border bg-tc-subtle hover:border-tc-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tc-accent"
          >
            <RotateCcw size={18} />
          </button>
        </div>
      </section>
    </main>
  );
}
