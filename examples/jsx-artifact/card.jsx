// No imports at all: React's automatic runtime and Tailwind are always available.
export default function Card() {
  return (
    <main className="min-h-screen grid place-items-center p-6 bg-tc-page text-tc-text">
      <article className="w-full max-w-md overflow-hidden rounded-tc-lg border border-tc-border bg-tc-surface">
        <div className="h-28 bg-linear-to-br from-tc-accent to-tc-active" aria-hidden="true" />
        <div className="p-6">
          <span className="inline-flex items-center rounded-full bg-tc-active px-3 py-1 text-xs font-medium text-tc-accent">
            Shared artifact
          </span>
          <h1 className="mt-3 text-2xl font-semibold tracking-tight">Quarterly notes</h1>
          <p className="mt-2 leading-relaxed text-tc-muted">
            A card styled only with Tailwind classes. The colours come from the TinyCloud
            tokens, so it follows light and dark with your system.
          </p>
          <dl className="mt-5 grid grid-cols-2 gap-4 border-t border-tc-border pt-4 text-sm">
            <div>
              <dt className="text-tc-muted">Shared by</dt>
              <dd className="font-medium">An agent</dd>
            </div>
            <div>
              <dt className="text-tc-muted">Expires</dt>
              <dd className="font-medium">In 7 days</dd>
            </div>
          </dl>
          <button
            type="button"
            className="mt-6 h-11 w-full rounded-full bg-tc-accent font-medium text-tc-on-accent transition-colors hover:bg-tc-accent-hover focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tc-accent"
          >
            Open
          </button>
        </div>
      </article>
    </main>
  );
}
