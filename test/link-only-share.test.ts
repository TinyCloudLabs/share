import type { CreateBearerShareResult } from "@tinycloud/share-cli";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  copyWithFallback,
  createLinkOnlyShare,
  type CreateShare,
} from "../src/share/link-only.js";
import { resolveShare } from "../src/viewer/resolve.js";

const SHARE_ORIGIN = "https://share.tinycloud.xyz";
const LINK =
  `${SHARE_ORIGIN}/s/bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` +
  "#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function result(url = LINK): CreateBearerShareResult {
  return {
    url,
    shareId: "share-id",
    envelopeCid:
      "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    contentCid:
      "bafkreibbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    expiry: "2026-07-30T00:00:00.000Z",
    registryDeleteAfter: "2026-07-30T00:00:00.000Z",
    envelope: {} as CreateBearerShareResult["envelope"],
  };
}

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

/**
 * Every place a secret could be read out of the live document: serialized
 * markup, every attribute value, and the live `value` property of every form
 * control (property assignment never shows up in `outerHTML`).
 */
function domExposure(): string {
  const parts: string[] = [document.documentElement.outerHTML];
  for (const node of Array.from(document.querySelectorAll("*"))) {
    for (const attribute of Array.from(node.attributes)) parts.push(attribute.value);
    const value: unknown = (node as Partial<HTMLInputElement>).value;
    if (typeof value === "string") parts.push(value);
  }
  return parts.join("\n");
}

describe("clipboard fallback (TC-297)", () => {
  it("never exposes the complete share URL to the DOM while copying", async () => {
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn(async () => Promise.reject(new Error("denied"))),
      },
    });

    const snapshots: string[] = [];
    let copied: string | undefined;
    // Stand in for the browser: `execCommand("copy")` dispatches a cancelable
    // `copy` event synchronously, then copies whatever the handler left behind.
    const execCommand = vi.fn((command: string) => {
      snapshots.push(domExposure());
      if (command !== "copy") return false;
      const event = new Event("copy", { bubbles: true, cancelable: true });
      Object.defineProperty(event, "clipboardData", {
        configurable: true,
        value: {
          setData: (format: string, data: string) => {
            expect(format).toBe("text/plain");
            copied = data;
          },
        },
      });
      document.dispatchEvent(event);
      snapshots.push(domExposure());
      return true;
    });
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: execCommand,
    });

    try {
      await copyWithFallback(LINK);

      expect(execCommand).toHaveBeenCalledWith("copy");
      // No snapshot of the document ever contained the link, not even the key
      // fragment or the envelope CID on their own.
      expect(snapshots).not.toHaveLength(0);
      for (const snapshot of snapshots) {
        expect(snapshot).not.toContain(LINK);
        expect(snapshot).not.toContain(LINK.split("#k=")[1]);
        expect(snapshot).not.toContain("bafkreiaaaaaaaa");
      }
      expect(domExposure()).not.toContain(LINK);
      // …and the clipboard still received the real link.
      expect(copied).toBe(LINK);
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  });

  it("rejects when the copy event never delivers the payload", async () => {
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn(async () => Promise.reject(new Error("denied"))),
      },
    });
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: vi.fn(() => true),
    });

    try {
      await expect(copyWithFallback(LINK)).rejects.toThrow(/clipboard/i);
      expect(document.body.textContent).not.toContain(LINK);
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  });

  it("leaves no node behind and restores the caller's selection", async () => {
    const originalClipboard = navigator.clipboard;
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: vi.fn(async () => Promise.reject(new Error("denied"))),
      },
    });
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: vi.fn(() => {
        const event = new Event("copy", { bubbles: true, cancelable: true });
        Object.defineProperty(event, "clipboardData", {
          configurable: true,
          value: { setData: () => undefined },
        });
        document.dispatchEvent(event);
        return true;
      }),
    });

    const paragraph = document.createElement("p");
    paragraph.textContent = "the user had selected this";
    document.body.append(paragraph);
    const range = document.createRange();
    range.selectNodeContents(paragraph);
    document.getSelection()?.removeAllRanges();
    document.getSelection()?.addRange(range);

    try {
      await copyWithFallback(LINK);
      expect(document.body.children).toHaveLength(1);
      expect(String(document.getSelection())).toBe("the user had selected this");
    } finally {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: originalClipboard,
      });
    }
  });
});

describe("link-only creation and recipient recovery", () => {
  // Kept from the deleted mountLinkOnlyShare suite (TC-304): these validation
  // rules belong to createLinkOnlyShare, not to the dead sender UI that used
  // to drive them through a form submit.
  it.each([
    [new File([], "empty.txt", { type: "text/plain" }), /non-empty/],
    [
      new File([new Uint8Array(100 * 1024 * 1024 + 1)], "oversized.txt", {
        type: "text/plain",
      }),
      /no larger than 100 MB/,
    ],
    [new File(["plain"], "image.png", { type: "image/png" }), /\.txt/],
    [new File([new Uint8Array([0xff])], "bad.txt"), /UTF-8/],
  ])("rejects malformed or oversized input before encryption", async (file, copy) => {
    const createShare = vi.fn<CreateShare>(async () => result());
    await expect(
      createLinkOnlyShare(file, { origin: SHARE_ORIGIN, createShare, expiresAt: new Date("2030-07-30T00:00:00.000Z") }),
    ).rejects.toThrow(copy);
    expect(createShare).not.toHaveBeenCalled();
  });

  it("accepts an exact 100 MiB binary file and rejects 100 MiB plus one byte before upload", async () => {
    const createShare = vi.fn<CreateShare>(async () => result());
    const expiresAt = new Date("2030-07-30T00:00:00.000Z");
    const exact = await createLinkOnlyShare(new File([new Uint8Array(100 * 1024 * 1024)], "boundary.bin"), { origin: SHARE_ORIGIN, allowBinary: true, createShare, expiresAt });
    expect(exact.url).toBe(LINK);
    expect(createShare).toHaveBeenCalledOnce();
    createShare.mockClear();
    await expect(createLinkOnlyShare(new File([new Uint8Array(100 * 1024 * 1024 + 1)], "over.bin"), { origin: SHARE_ORIGIN, allowBinary: true, createShare, expiresAt })).rejects.toThrow(/no larger than 100 MB/);
    expect(createShare).not.toHaveBeenCalled();
  });

  it("forwards the supplied expiry to bearer creation verbatim", async () => {
    const expiresAt = new Date("2030-07-30T00:00:00.000Z");
    let received: Date | undefined;
    const createShare: CreateShare = async (input) => {
      received = input.expiresAt;
      return result();
    };

    await createLinkOnlyShare(new File(["expiry"], "expiry.txt"), {
      origin: SHARE_ORIGIN,
      expiresAt,
      createShare,
    });

    expect(received).toBe(expiresAt);
  });

  it("uploads only sealed bytes through the authenticated route and recovers the marker in a fresh resolve", async () => {
    const registry: DevRegistry = createDevRegistry();
    const requests: Array<{ url: string; body: Uint8Array; init?: RequestInit }> = [];
    const authenticatedRegistryFetch: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const body = new Uint8Array(await new Response(init?.body).arrayBuffer());
      requests.push({
        url: url.toString(),
        body,
        ...(init === undefined ? {} : { init }),
      });
      const target = new URL(
        url.pathname.replace("/api/share/link-only/registry", ""),
        "http://registry.local",
      );
      return registry.handler(
        new Request(target, {
          ...init,
          body,
          duplex: "half",
        } as RequestInit),
      );
    };
    const marker = "link-only-production-marker";
    const created = await createLinkOnlyShare(
      new File([`# Private note\n\n${marker}\n`], "private-note.md", {
        type: "text/markdown",
      }),
      {
        origin: SHARE_ORIGIN,
        // `now` is injected so the envelope's own timestamps stay deterministic.
        // `expiresAt` deliberately is NOT: it becomes the `x-delete-after` header,
        // which the registry Worker validates against the REAL clock —
        // `retentionExpiry` (worker.ts:95) requires
        // `Date.now() < expiry <= Date.now() + LINK_RETENTION_LIMIT_MS` (8 days).
        // A hardcoded date is a time bomb in both directions: it goes stale and
        // 400s once it passes, and a far-future constant exceeds the retention
        // window and 400s immediately. Keep this relative to real time.
        now: () => Date.parse("2026-07-23T20:00:00.000Z"),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        fetchFn: authenticatedRegistryFetch,
      },
    );

    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(new URL(request.url).pathname).toBe(
        "/api/share/link-only/registry/blobs",
      );
      expect(request.init?.credentials).toBe("include");
      expect(request.init?.referrerPolicy).toBe("no-referrer");
      expect(request.url).not.toContain("#");
      expect(new TextDecoder().decode(request.body)).not.toContain(marker);
    }
    const fragment = created.url.split("#k=")[1]!;
    expect(fragment).toHaveLength(43);
    expect(
      requests.some((request) => new TextDecoder().decode(request.body).includes(fragment)),
    ).toBe(false);

    const registryFetch: typeof fetch = async (input, init) =>
      registry.handler(new Request(input, init));
    const recovered = await resolveShare(created.url, {
      registryBaseUrl: "http://registry.local",
      fetchFn: registryFetch,
      now: () => Date.parse("2026-07-23T20:01:00.000Z"),
    });
    expect(recovered.state).toBe("ok");
    if (recovered.state !== "ok") throw new Error("expected recovered share");
    expect(recovered.content).toBe(`# Private note\n\n${marker}\n`);
    expect(recovered.envelope.display.filename).toBe("private-note.md");
  });
});
