/**
 * The build-time manifest of the JSX runtime files (vite.config.ts serves it as
 * a virtual module). Lives in the lazy JSX chunk, never the viewer root.
 */
import manifest from "virtual:tc-jsx-manifest";

export { manifest };
