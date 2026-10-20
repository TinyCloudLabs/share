// Shared React: one instance for the runtime, react-dom and every library.
// The element-creating functions are wrapped: a host element that would make the browser ask for a URL
// (url-guard.ts) is not rendered. Everything else is React unchanged.
import react from "react";
import jsxRuntime from "react/jsx-runtime";
import jsxDevRuntime from "react/jsx-dev-runtime";
import { guardedElementFunction } from "../url-guard.ts";

const refused = (reason) => {
  try { console.warn(`This page tried to load something from the network, so that element was not shown: ${reason}`); } catch { /* no console */ }
};
const guard = (original) => (typeof original === "function" ? guardedElementFunction(original, refused) : original);

const guardedReact = { ...react, createElement: guard(react.createElement) };
const guardedJsx = { ...jsxRuntime, jsx: guard(jsxRuntime.jsx), jsxs: guard(jsxRuntime.jsxs) };
const guardedJsxDev = { ...jsxDevRuntime, jsxDEV: guard(jsxDevRuntime.jsxDEV) };
export default { "react": guardedReact, "react/jsx-runtime": guardedJsx, "react/jsx-dev-runtime": guardedJsxDev };
