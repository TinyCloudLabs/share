export const NODE_ERROR_CATEGORIES = [
  "invalid_content_source",
  "invalid_holder_proof",
  "policy_denied",
  "read_denied",
  "capability_unavailable",
  "invitation_authorization_invalid",
] as const;

type AllowlistedNodeErrorCategory = (typeof NODE_ERROR_CATEGORIES)[number];
export type NodeErrorCategory = AllowlistedNodeErrorCategory | "unknown";

export type RedactedNodeFailure = {
  route: string;
  status: number;
  category: NodeErrorCategory;
};

const MAX_ERROR_BODY_BYTES = 4096;

function exactNodeErrorCategory(body: unknown): NodeErrorCategory {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return "unknown";
  if (Object.keys(body).length !== 1 || !Object.hasOwn(body, "error")) return "unknown";
  const error = (body as { error?: unknown }).error;
  if (error === null || typeof error !== "object" || Array.isArray(error)) return "unknown";
  if (Object.keys(error).length !== 1 || !Object.hasOwn(error, "code")) return "unknown";
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" && NODE_ERROR_CATEGORIES.includes(code as AllowlistedNodeErrorCategory)
    ? code as AllowlistedNodeErrorCategory
    : "unknown";
}

export async function redactedNodeFailure(
  route: string,
  response: Response,
): Promise<RedactedNodeFailure> {
  let category: NodeErrorCategory = "unknown";
  try {
    const body = await response.arrayBuffer();
    if (body.byteLength <= MAX_ERROR_BODY_BYTES) {
      category = exactNodeErrorCategory(JSON.parse(new TextDecoder().decode(body)));
    }
  } catch {
    category = "unknown";
  }
  return { route, status: response.status, category };
}

export async function captureFirstRedactedNodeFailure(
  current: RedactedNodeFailure | undefined,
  route: string,
  response: Response,
): Promise<RedactedNodeFailure | undefined> {
  if (current !== undefined || response.ok) return current;
  try {
    return await redactedNodeFailure(route, response.clone());
  } catch {
    return { route, status: response.status, category: "unknown" };
  }
}
