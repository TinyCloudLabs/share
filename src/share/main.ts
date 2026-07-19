import "../email-share/sender.css";
import { createHttpTransport } from "../email-share/transport.js";
import { mountSender } from "../email-share/view.js";

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");

const nodeOrigin = (import.meta.env.VITE_TINYCLOUD_NODE_ORIGIN as string | undefined) ?? "";
const credentialsOrigin = (import.meta.env.VITE_OPEN_CREDENTIALS_ORIGIN as string | undefined) ?? "";
const transport = createHttpTransport({ nodeOrigin: nodeOrigin || "https://node.example", credentialsOrigin: credentialsOrigin || "https://credentials.example" });

mountSender(root, {
  transport,
  uploadEnvelope: async () => {
    throw new Error("registry-upload-adapter-not-configured");
  },
});
