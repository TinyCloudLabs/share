import { describe, expect, it } from "vitest";

import { canonicalJson, requestHash } from "../src/courier/canonical.ts";
import {
  approvalFile, EXT, strictText, keys, multiLine, oneLine, parseApproval, parseKey, parseMessage, parseRequest, parseTask,
  requestStanding, ulidTime,
} from "../src/courier/model.ts";
import { loadOverview, loadThread } from "../src/courier/service.ts";
import type { CourierStore } from "../src/courier/store.ts";

const T = (n: number): string => `01J9ZC4K7T3QZ5W6M8R2N1B0${String(n).padStart(2, "0")}`.slice(0, 26);
const THREAD = T(10);
const MSG_ME = T(21);
const MSG_PEER = T(20);
const TASK = T(22);
const REQ = T(30);

describe("canonical JSON and the request hash (shared vector with packages/courier)", () => {
  it("refuses what has no honest canonical form, so two different files can't hash the same", () => {
    // JSON.parse('1e999') is Infinity and JSON.stringify writes it as null: {"n":1e999} must not equal {"n":null}
    expect(() => canonicalJson(JSON.parse('{"n":1e999}'))).toThrow();
    expect(() => canonicalJson({ n: Number.NaN })).toThrow();
    expect(canonicalJson({ n: null })).toBe('{"n":null}');
    const nest = (levels: number): unknown => { let value: unknown = 1; for (let level = 0; level < levels; level += 1) value = [value]; return value; };
    expect(() => canonicalJson(nest(64))).not.toThrow();
    expect(() => canonicalJson(nest(65))).toThrow();
    expect(() => canonicalJson(nest(20_000))).toThrow();
  });
  it("keeps a parsed __proto__ key as an ordinary property, as the CLI's canonicalJson does", () => {
    expect(canonicalJson(JSON.parse('{"__proto__":{"x":1},"a":1}'))).toBe('{"__proto__":{"x":1},"a":1}');
  });
  it("sorts keys recursively and drops whitespace", () => {
    expect(canonicalJson({ b: 1, a: [{ d: 2, c: "x" }] })).toBe('{"a":[{"c":"x","d":2}],"b":1}');
  });
  it("hashes the canonical text with SHA-256 as lowercase hex, independent of key order", async () => {
    const one = await requestHash({ id: REQ, action: "merge #20", n: [1, 2] });
    const two = await requestHash({ n: [1, 2], action: "merge #20", id: REQ });
    expect(one).toBe(two);
    expect(one).toMatch(/^[0-9a-f]{64}$/);
    expect(await requestHash({ id: REQ, action: "merge #21", n: [1, 2] })).not.toBe(one);
    // The vector the CLI worker mirrors: sha256 of {"a":[{"c":"x","d":2}],"b":1}
    expect(await requestHash({ b: 1, a: [{ d: 2, c: "x" }] })).toBe("ea8702e7f75afcfa88e6b612e382f127e636623fb4d70353ae0bcc0dea758935");
  });
});

describe("text an approval depends on is checked, never repaired", () => {
  it("accepts plain text exactly as written and nothing else", () => {
    expect(strictText("Docs-only README change", 200)).toBe("Docs-only README change");
    expect(strictText("\u05D1\u05D3\u05D9\u05E7\u05D4", 200)).toBe("\u05D1\u05D3\u05D9\u05E7\u05D4"); // Hebrew letters are visible text
    expect(strictText("line one\nline two", 200, { lines: true })).toBe("line one\nline two");
    expect(strictText("line one\nline two", 200)).toBeUndefined(); // a one-line field has no line breaks
    expect(strictText("x".repeat(200), 200)).toBeDefined();
    expect(strictText("x".repeat(201), 200)).toBeUndefined(); // never shortened
    expect(strictText("", 200)).toBeUndefined();
    expect(strictText(["a"], 200)).toBeUndefined();
  });
  it("refuses every kind of invisible or overdrawing character", () => {
    const refused: [string, string][] = [
      ["tag characters", `a${String.fromCodePoint(0xe0061)}`], ["a variation selector", "a\uFE0F"], ["a supplementary variation selector", `a${String.fromCodePoint(0xe0100)}`],
      ["a combining grapheme joiner", "a\u034F"], ["a Khmer filler", "a\u17B4"], ["a Hangul filler", "a\u3164"], ["a zero-width joiner", "a\u200D"],
      ["a bidi isolate", "a\u2066b"], ["a right-to-left mark", "a\u200F"], ["a byte order mark", "a\uFEFF"], ["a soft hyphen", "a\u00AD"],
      ["a line separator", "a\u2028b"], ["a private-use character", "a\uE000"], ["an unassigned code point", "a\u0378"], ["a lone surrogate", "a\uD800"],
      ["a Braille blank", "a\u2800"], ["an object replacement character", "a\uFFFC"], ["a musical null notehead", `a${String.fromCodePoint(0x1d159)}`], ["a no-break space", "a\u00A0b"], ["a NUL", "a\u0000"], ["a tab", "a\tb"], ["decomposed text (not NFC)", "e\u0301"], ["four stacked combining marks", "a\u0301\u0302\u0303\u0304"],
    ];
    for (const [name, value] of refused) expect(strictText(value, 200, { lines: true }), name).toBeUndefined();
    expect(strictText("a\u0301\u0302\u0303", 200)).toBeUndefined(); // all marks are refused by the frozen category allow-list
  });
  it("makes the same characters visible, not gone, when it only shows them", () => {
    expect(oneLine(`x${String.fromCodePoint(0xe0061)}y\u200D\uFE0Fz`, 50)).toBe("x⟦U+E0061⟧y⟦U+200D⟧⟦U+FE0F⟧z");
    expect(oneLine(`a${"\u0301".repeat(6)}`, 50)).toContain("⟦many combining marks⟧");
  });
});

describe("text from a peer is escaped, not trusted", () => {
  it("shows bidi and control characters as visible escapes and flattens line breaks", () => {
    expect(oneLine("a\u202Eb\u0000c\nd", 50)).toBe("a⟦U+202E⟧b⟦U+0000⟧c d");
    expect(multiLine("a\u2066b\r\nc", 50)).toBe("a⟦U+2066⟧b\nc");
  });
  it("caps the length", () => {
    expect(oneLine("x".repeat(500), 20)).toHaveLength(20);
  });
});

describe("mailbox keys", () => {
  it("reads only the keys the page uses", () => {
    expect(parseKey(`xyz.tinycloud.courier/to/hunter/threads/${THREAD}/msg/${MSG_ME}.json`)).toMatchObject({ side: "me", peer: "hunter", part: "msg", id: MSG_ME });
    expect(parseKey(`xyz.tinycloud.courier/me/mirror/hunter/threads/${THREAD}/task/${TASK}.json`)).toMatchObject({ side: "peer", part: "task" });
    expect(parseKey(`xyz.tinycloud.courier/me/requests/${REQ}.json`)).toEqual({ kind: "request", id: REQ });
    expect(parseKey("xyz.tinycloud.courier/me/orders/hunter.md")).toEqual({ kind: "orders", peer: "hunter" });
    expect(parseKey("xyz.tinycloud.courier/to/hunter/receipts.json")).toBeUndefined();
    expect(parseKey(`xyz.tinycloud.courier/to/hunter/threads/${THREAD}/files/x.bin`)).toBeUndefined();
    expect(parseKey(`xyz.tinycloud.courier/to/../threads/${THREAD}/meta.json`)).toBeUndefined();
    expect(parseKey(`other/to/hunter/threads/${THREAD}/meta.json`)).toBeUndefined();
  });
});

const msg = (id: string, text: string, intent = "request") => ({ messageId: id, contextId: THREAD, role: "ROLE_USER", parts: [{ text, mediaType: "text/markdown" }], referenceTaskIds: [], metadata: { [EXT]: { from: { label: "Hunter's agent" }, intent, asks: [{ id: "a1", title: "Merge" }] } } });
const task = (id: string, state: string) => ({ id, contextId: THREAD, status: { state: `TASK_STATE_${state}`, timestamp: "2026-10-20T10:00:00Z" }, metadata: { [EXT]: {} } });

function fakeStore(files: Record<string, unknown>, onList?: () => void): CourierStore {
  return {
    async list() { onList?.(); return { keys: Object.keys(files), truncated: false }; },
    async readJson(key) { return files[key]; },
    async readOrders() { return undefined; },
    async createApproval() { return "created"; },
    async writeOrders() { /* not used */ },
  };
}

describe("a thread is both sides' files merged by ULID", () => {
  const files: Record<string, unknown> = {
    [keys.thread("me", "hunter", THREAD, "meta", THREAD)]: { subject: "Handoff", startedBy: {}, createdAt: "2026-10-20T09:00:00Z" },
    [keys.thread("me", "hunter", THREAD, "msg", MSG_ME)]: msg(MSG_ME, "my reply", "answer"),
    [keys.thread("peer", "hunter", THREAD, "msg", MSG_PEER)]: msg(MSG_PEER, "their ask"),
    [keys.thread("me", "hunter", THREAD, "task", TASK)]: task(TASK, "AUTH_REQUIRED"),
  };
  it("orders messages and tasks by id and marks sides", async () => {
    const detail = await loadThread(fakeStore(files), { peer: "hunter", threadId: THREAD });
    expect(detail.subject).toBe("Handoff");
    expect(detail.timeline.map((item) => `${item.kind}:${item.id.slice(-2)}`)).toEqual(["message:20", "message:21", "task:22"]);
    const first = detail.timeline[0]!;
    expect(first.kind === "message" && first.message.side).toBe("peer");
  });
  it("lists the thread with its open tasks, last activity and a needs-you count", async () => {
    const request = { id: REQ, peer: "hunter", threadId: THREAD, taskId: TASK, verb: "merge", target: "tinycloudlabs/eliza#20", summary: "Docs only", action: "gh pr merge 20", reason: "ordered", risk: "redeploys", requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z", status: "pending" };
    const overview = await loadOverview(fakeStore({ ...files, [keys.request(REQ)]: request }), Date.parse("2026-10-20T12:00:00Z"));
    expect(overview.threads).toHaveLength(1);
    expect(overview.threads[0]).toMatchObject({ peer: "hunter", subject: "Handoff", openTasks: 1, needsYou: 1 });
    expect(overview.requests[0]).toMatchObject({ standing: "pending", subject: "Handoff" });
    expect(overview.peers).toEqual(["hunter"]);
  });
  it("drops a message whose id disagrees with its file name", () => {
    expect(parseMessage("peer", MSG_PEER, msg(MSG_ME, "x"))).toBeUndefined();
    expect(parseTask("peer", TASK, task(MSG_ME, "WORKING"))).toBeUndefined();
  });
  it("treats an unknown task state as unknown and never as done", () => {
    expect(parseTask("me", TASK, task(TASK, "SPECIAL"))?.state).toBe("UNKNOWN");
  });
});

describe("requests and decisions", () => {
  const good = { id: REQ, peer: "hunter", threadId: THREAD, taskId: TASK, verb: "merge", target: "tinycloudlabs/eliza#20", summary: "Docs only", action: "gh pr merge 20", reason: "r", risk: "k", requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, status: "pending", createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z" };
  it("reads what a request approves only from a valid verb, target and summary, exactly as written", () => {
    expect(parseRequest(REQ, good)?.what).toEqual({ verb: "merge", target: "tinycloudlabs/eliza#20", summary: "Docs only" });
    const targets: Record<string, string> = { merge: "o/r#1", deploy: "wrangler:worker:prod", publish: "npm:@scope/pkg@1.2.3", spend: "spend:$20 of credits", other: "workflow:o/r:ci.yml" };
    for (const [verb, target] of Object.entries(targets)) expect(parseRequest(REQ, { ...good, verb, target })?.what?.verb, verb).toBe(verb);
    const exactly200 = "x".repeat(200);
    const target200 = `spend:${"x".repeat(194)}`;
    expect(target200).toHaveLength(200);
    expect(parseRequest(REQ, { ...good, verb: "spend", target: target200, summary: exactly200 })?.what).toEqual({ verb: "spend", target: target200, summary: exactly200 });
    expect(parseRequest(REQ, { ...good, verb: "spend", target: `${target200}x` })?.what).toBeUndefined();
    expect(parseRequest(REQ, { ...good, summary: `${exactly200}x` })?.what).toBeUndefined();
    expect(parseRequest(REQ, { ...good, target: `${exactly200}x` })?.what).toBeUndefined();
    expect(parseRequest(REQ, { ...good, summary: "a\u200Bb" })?.what).toBeUndefined();
    // the request is still readable, and still hashed whole: an unreviewable request keeps every stored field
    expect(parseRequest(REQ, { ...good, verb: "nuke" })?.raw).toEqual({ ...good, verb: "nuke" });
  });
  it("refuses a request whose id, handle or ids are not what a real one has", () => {
    expect(parseRequest(REQ, good)).toBeDefined();
    expect(parseRequest(REQ, { ...good, id: T(31) })).toBeUndefined();
    expect(parseRequest(REQ, { ...good, peer: "../x" })).toBeUndefined();
    expect(parseRequest(REQ, { ...good, threadId: "nope" })).toBeUndefined();
    expect(parseRequest(REQ, { ...good, expiresAt: "soon" })).toBeUndefined();
    // the free text is optional, but every other key is required and no other key is allowed
    const { action: _action, ...withoutAction } = good;
    expect(parseRequest(REQ, withoutAction)?.problem).toBeUndefined();
    const { status: _status, ...withoutStatus } = good;
    expect(parseRequest(REQ, withoutStatus)?.problem).toBe("fields");
    expect(parseRequest(REQ, { ...good, extra: 1 })?.problem).toBe("fields");
    expect(parseRequest(REQ, { ...good, action: "" })?.problem).toBe("text");
  });
  it("is pending until decided or 24 hours pass; a decision wins over expiry", () => {
    const request = parseRequest(REQ, good)!;
    const before = Date.parse("2026-10-20T12:00:00Z");
    expect(requestStanding(request, undefined, before)).toBe("pending");
    expect(requestStanding(request, undefined, Date.parse("2026-10-21T10:00:00Z"))).toBe("expired");
    expect(requestStanding(request, { requestId: REQ, decision: "denied", note: "", decidedAt: before }, before)).toBe("denied");
  });
  it("writes the decision file the CLI checks: requestId, requestHash, decision, note, decidedAt", async () => {
    const request = parseRequest(REQ, good)!;
    const hash = await requestHash(request.raw);
    const file = approvalFile(request, hash, "approved", "go ahead", Date.parse("2026-10-20T12:00:00Z"));
    expect(file).toEqual({ requestId: REQ, requestHash: hash, decision: "approved", note: "go ahead", decidedAt: "2026-10-20T12:00:00.000Z" });
    expect(parseApproval(REQ, file)).toMatchObject({ decision: "approved" });
    expect(parseApproval(REQ, { ...file, decision: "approve" })).toBeUndefined();
    expect(parseApproval(T(31), file)).toBeUndefined();
  });
  it("decodes the time a ULID starts with", () => {
    // The example in the ULID spec.
    expect(ulidTime("01ARYZ6S41TSV4RRFFQ69G5FAV")).toBe(1469918176385);
    expect(ulidTime("not-a-ulid")).toBeUndefined();
  });
});
