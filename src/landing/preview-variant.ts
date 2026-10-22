/**
 * Preview-only: lets a reviewer compare two wordings of the hero privacy sentence on one URL.
 * Loaded by main.ts only when the build sets VITE_HERO_PREVIEW=1; production builds do not
 * include this module. `?v=b` selects the alternative, anything else the default in index.html.
 */
import "./preview-variant.css";

const ALTERNATIVE_CLAUSE = "a link that no one else can open, not even TinyCloud";

export function mountPrivacyVariant(doc: Document = document, search: string = window.location.search): void {
  const clause = doc.getElementById("privacy-clause");
  if (!clause) return;
  const defaultClause = clause.textContent ?? "";
  const wording = new URLSearchParams(search).get("v") === "b" ? "b" : "a";
  if (wording === "b") clause.textContent = ALTERNATIVE_CLAUSE;

  const bar = doc.createElement("nav");
  bar.className = "preview-variant";
  bar.setAttribute("aria-label", "Preview: privacy wording");
  bar.append("Preview only. Privacy wording: ");
  for (const [id, label] of [["a", "A"], ["b", "B"]] as const) {
    const link = doc.createElement("a");
    link.href = id === "a" ? "?v=a" : "?v=b";
    link.textContent = label;
    if (id === wording) link.setAttribute("aria-current", "true");
    link.addEventListener("click", (event) => {
      event.preventDefault();
      clause.textContent = id === "a" ? defaultClause : ALTERNATIVE_CLAUSE;
      for (const other of bar.querySelectorAll("a")) other.removeAttribute("aria-current");
      link.setAttribute("aria-current", "true");
      history.replaceState(null, "", link.href);
    });
    bar.append(link);
  }
  doc.body.insertBefore(bar, doc.querySelector(".site-shell"));
}
