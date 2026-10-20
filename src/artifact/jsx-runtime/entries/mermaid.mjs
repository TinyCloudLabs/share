// Mermaid, initialised once from the TinyCloud tokens of the frame it runs in.
// Authors may call `mermaid.initialize(...)` again; securityLevel stays strict
// unless they change it, and nothing here reaches the network either way.
import mermaid from "mermaid";

const style = getComputedStyle(document.documentElement);
const token = (name, fallback) => style.getPropertyValue(name).trim() || fallback;
mermaid.initialize({
  startOnLoad: false,
  securityLevel: "strict",
  theme: "base",
  fontFamily: token("--tc-font-sans", "sans-serif"),
  themeVariables: {
    background: token("--tc-color-surface", "#ffffff"),
    primaryColor: token("--tc-color-surface-active", "#eef4ff"),
    primaryTextColor: token("--tc-color-text", "#1a1c21"),
    primaryBorderColor: token("--tc-color-accent", "#2a56f6"),
    lineColor: token("--tc-color-text-muted", "#64748b"),
    secondaryColor: token("--tc-color-surface-subtle", "#f1f5f9"),
    tertiaryColor: token("--tc-color-surface", "#ffffff"),
    noteBkgColor: token("--tc-color-surface-subtle", "#f1f5f9"),
    noteTextColor: token("--tc-color-text", "#1a1c21"),
    textColor: token("--tc-color-text", "#1a1c21"),
    edgeLabelBackground: token("--tc-color-surface", "#ffffff"),
  },
});
export default mermaid;
