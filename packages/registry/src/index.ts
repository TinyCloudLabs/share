// Browser-safe surface only. The node-only dev server is a separate entry:
// import { createDevRegistry, serveDevRegistry } from "@tinycloud/share-registry/dev-server";
export {
  DEFAULT_MAX_BLOB_BYTES,
  MAX_SHARE_CONTENT_BYTES,
  RAW_BLOCK_CONTENT_TYPE,
  SEALED_BLOB_OVERHEAD_BYTES,
  fetchBlob,
  putBlob,
  type RegistryClientOptions,
} from "./client.js";
export {
  BlobTooLargeError,
  CidMismatchError,
  RegistryError,
  RegistryHttpError,
} from "./errors.js";
