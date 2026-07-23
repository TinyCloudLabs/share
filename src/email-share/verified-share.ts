import type { ContentSource, TrustedNode } from "./protocol.js";

export interface VerifiedExactEmailShare {
  readonly shareId: string;
  readonly shareCid: string;
  readonly policyCid: string;
  readonly recipientEmail: string;
  readonly recipientHint: string;
  readonly expiry: string;
  readonly nodeOrigin: string;
  readonly nodeAudience: string;
  readonly requestOrigin: string;
  readonly delegationCid: string;
  readonly authorityMaterialHandle: string;
  readonly authorityMaterialDigest: string;
  readonly contentSource: ContentSource;
  readonly contentSourceDigest: string;
  readonly action: "tinycloud.kv/get" | "tinycloud.sql/read";
  readonly resource: string;
  readonly trustedNode: TrustedNode;
}
