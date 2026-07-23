#!/usr/bin/env node
// Bin shim: the package ships TS source (no build step in this prototype),
// so register tsx's ESM loader, then hand argv to the real CLI.
import { register } from "tsx/esm/api";

register();
const { main } = await import("../src/cli.ts");
process.exitCode = await main(process.argv.slice(2));
