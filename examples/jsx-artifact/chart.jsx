import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const data = [
  { week: "W1", shared: 12, opened: 7 },
  { week: "W2", shared: 19, opened: 13 },
  { week: "W3", shared: 24, opened: 18 },
  { week: "W4", shared: 31, opened: 25 },
  { week: "W5", shared: 38, opened: 33 },
  { week: "W6", shared: 47, opened: 41 },
];

// recharts draws SVG from the bundled library; colours come from the tokens.
export default function Chart() {
  return (
    <main className="min-h-screen p-6 bg-tc-page text-tc-text">
      <section className="mx-auto max-w-3xl rounded-tc-lg border border-tc-border bg-tc-surface p-6">
        <header className="mb-4">
          <h1 className="text-xl font-semibold tracking-tight">Shares per week</h1>
          <p className="text-sm text-tc-muted">Links created and opened over six weeks.</p>
        </header>
        <div style={{ height: 320 }} data-testid="chart">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <defs>
                <linearGradient id="shared" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--tc-color-accent)" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="var(--tc-color-accent)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--tc-color-border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="week" stroke="var(--tc-color-text-muted)" tickLine={false} axisLine={false} />
              <YAxis stroke="var(--tc-color-text-muted)" tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={{
                  background: "var(--tc-color-surface)",
                  border: "1px solid var(--tc-color-border)",
                  borderRadius: "var(--tc-radius-md)",
                  color: "var(--tc-color-text)",
                }}
              />
              <Area type="monotone" dataKey="shared" stroke="var(--tc-color-accent)" strokeWidth={2} fill="url(#shared)" />
              <Area type="monotone" dataKey="opened" stroke="var(--tc-color-status-success)" strokeWidth={2} fill="none" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <ul className="mt-4 flex gap-5 text-sm text-tc-muted">
          <li className="flex items-center gap-2"><span className="size-2.5 rounded-full bg-tc-accent" /> Shared</li>
          <li className="flex items-center gap-2"><span className="size-2.5 rounded-full bg-tc-success" /> Opened</li>
        </ul>
      </section>
    </main>
  );
}
