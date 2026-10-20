// Shared React: one instance for the runtime, react-dom and every library.
import react from "react";
import jsxRuntime from "react/jsx-runtime";
import jsxDevRuntime from "react/jsx-dev-runtime";
export default { "react": react, "react/jsx-runtime": jsxRuntime, "react/jsx-dev-runtime": jsxDevRuntime };
