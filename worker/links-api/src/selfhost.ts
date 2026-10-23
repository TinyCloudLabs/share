import { createSelfHost } from "./selfhost-server.ts";

// Run: LINKS_DB_PATH=links.sqlite ADDRESS_SALT=<16+ chars> node src/selfhost.ts
const dbPath = process.env["LINKS_DB_PATH"];
if (!dbPath) {
  console.error("LINKS_DB_PATH is required");
  process.exit(1);
}
const port = Number(process.env["PORT"] ?? 8787);
const host = process.env["HOST"] ?? "127.0.0.1";
const selfHost = createSelfHost({ env: process.env, dbPath });
selfHost.server.listen(port, host, () => {
  console.log(JSON.stringify({ event: "links.listening", host, port }));
});
