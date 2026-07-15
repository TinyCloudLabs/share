#!/usr/bin/env node
// Bin shim: the package ships TS source (no build step in this prototype),
// so register tsx's ESM loader, then hand argv to the real CLI.
import { register } from "tsx/esm/api";

register();
const { main } = await import("../src/cli.ts");
const {
  RECIPIENT_DID_ALLOWED_NODE_ORIGINS,
  RECIPIENT_DID_SENDER_ADAPTER,
} = await import("../src/sdk-adapter.ts");
process.exitCode = await main(process.argv.slice(2), {
  allowedNodeOrigins: RECIPIENT_DID_ALLOWED_NODE_ORIGINS,
  ...(RECIPIENT_DID_SENDER_ADAPTER !== undefined
    ? { recipientDidAdapter: RECIPIENT_DID_SENDER_ADAPTER }
    : {}),
});
