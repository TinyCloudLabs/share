import { Cloud, FileText, KeyRound, Link2, Lock, Share2, ShieldCheck, Sparkles } from "lucide-react";

const icons = [
  { Icon: Cloud, name: "Cloud", note: "Your space" },
  { Icon: Link2, name: "Link", note: "Anyone with it" },
  { Icon: Lock, name: "Lock", note: "Encrypted" },
  { Icon: KeyRound, name: "Key", note: "Stays with you" },
  { Icon: ShieldCheck, name: "Shield", note: "Sandboxed" },
  { Icon: FileText, name: "File", note: "One document" },
  { Icon: Share2, name: "Share", note: "Revocable" },
  { Icon: Sparkles, name: "Sparkles", note: "Made by an agent" },
];

export default function Icons() {
  return (
    <main className="min-h-screen p-6 bg-tc-page text-tc-text">
      <div className="mx-auto max-w-3xl">
        <h1 className="text-xl font-semibold tracking-tight">lucide-react</h1>
        <p className="mb-5 text-sm text-tc-muted">Icons are bundled with Share, so they draw with no network.</p>
        <ul className="grid grid-cols-2 sm:grid-cols-4 gap-3" data-testid="icons">
          {icons.map(({ Icon, name, note }) => (
            <li key={name} className="rounded-tc-md border border-tc-border bg-tc-surface p-4">
              <Icon size={28} strokeWidth={1.75} className="text-tc-accent" aria-hidden="true" />
              <p className="mt-3 font-medium">{name}</p>
              <p className="text-sm text-tc-muted">{note}</p>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}
