import mermaid from "mermaid";

const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
mermaid.initialize({
  startOnLoad: true,
  theme: dark ? "dark" : "neutral",
  securityLevel: "strict",
  fontFamily: "system-ui, -apple-system, sans-serif",
});

// Sticky-TOC scrollspy
const links = Array.from(
  document.querySelectorAll<HTMLAnchorElement>("nav.toc ol a[href^='#']")
);
const map = new Map<string, HTMLAnchorElement>();
links.forEach((a) => map.set(a.getAttribute("href")!.slice(1), a));
const targets = Array.from(map.keys())
  .map((id) => document.getElementById(id))
  .filter((t): t is HTMLElement => t !== null);
if ("IntersectionObserver" in window && targets.length) {
  let current: HTMLAnchorElement | null = null;
  const visible = new Set<string>();
  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) visible.add(e.target.id);
        else visible.delete(e.target.id);
      });
      const first = targets.find((t) => visible.has(t.id));
      if (first && map.get(first.id) !== current) {
        if (current) current.classList.remove("active");
        current = map.get(first.id)!;
        current.classList.add("active");
      }
    },
    { rootMargin: "-10% 0px -60% 0px" }
  );
  targets.forEach((t) => io.observe(t));
}
