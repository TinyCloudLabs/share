import type { CreateBearerShareResult } from "@tinycloud/share-cli";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createLinkOnlyShare,
  mountLinkOnlyShare,
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

function root(): HTMLElement {
  const node = document.createElement("div");
  document.body.append(node);
  return node;
}

function choose(input: HTMLInputElement, file: File): void {
  Object.defineProperty(input, "files", {
    configurable: true,
    value: [file],
  });
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

async function submit(form: HTMLFormElement): Promise<void> {
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => {
    expect(
      form.querySelector<HTMLElement>(".sender-status")?.dataset.state,
    ).toBeDefined();
  });
}

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("link-only sender", () => {
  it("keeps Notify by email disabled, unchecked, described, and outside link creation", async () => {
    const createShare = vi.fn<CreateShare>(async () => result());
    const view = root();
    mountLinkOnlyShare(view, {
      openKeyAddress: "0x1111111111111111111111111111111111111111",
      origin: SHARE_ORIGIN,
      createShare,
    });

    const notify = view.querySelector<HTMLInputElement>("#notify-by-email")!;
    expect(notify.disabled).toBe(true);
    expect(notify.checked).toBe(false);
    expect(notify.getAttribute("aria-describedby")).toBe("notify-by-email-help");
    expect(view.querySelector('label[for="notify-by-email"]')?.textContent).toBe(
      "Notify by email",
    );
    expect(view.querySelector("#notify-by-email-help")?.textContent).toContain(
      "Coming soon",
    );

    const input = view.querySelector<HTMLInputElement>('input[type="file"]')!;
    choose(input, new File(["unique-marker"], "note.txt", { type: "text/plain" }));
    await submit(view.querySelector<HTMLFormElement>("form")!);

    await vi.waitFor(() => expect(createShare).toHaveBeenCalledOnce());
    expect(notify.checked).toBe(false);
    expect(view.querySelector<HTMLTextAreaElement>("#generated-share-link")?.value).toBe(
      LINK,
    );
    expect(view.textContent).toContain("No email notification was sent.");
    expect(JSON.stringify(createShare.mock.calls[0]?.[0])).not.toContain("email");
  });

  it("announces reliable copy success and exposes a clear another-file action", async () => {
    const copyText = vi.fn(async () => undefined);
    const view = root();
    mountLinkOnlyShare(view, {
      openKeyAddress: "0x1111111111111111111111111111111111111111",
      origin: SHARE_ORIGIN,
      createShare: async () => result(),
      copyText,
    });
    choose(
      view.querySelector<HTMLInputElement>('input[type="file"]')!,
      new File(["copy me"], "copy.md", { type: "text/markdown" }),
    );
    await submit(view.querySelector<HTMLFormElement>("form")!);
    const copy = await vi.waitFor(() => {
      const button = Array.from(view.querySelectorAll("button")).find(
        (candidate) => candidate.textContent === "Copy link",
      );
      expect(button).toBeDefined();
      return button as HTMLButtonElement;
    });
    copy.click();
    await vi.waitFor(() => expect(copyText).toHaveBeenCalledWith(LINK));
    expect(view.querySelector(".copy-status")?.textContent).toBe(
      "Link copied to clipboard.",
    );
    expect(view.textContent).toContain("Share another file");
  });

  it("reports copy failures accessibly without losing the generated link", async () => {
    const view = root();
    mountLinkOnlyShare(view, {
      openKeyAddress: "0x1111111111111111111111111111111111111111",
      origin: SHARE_ORIGIN,
      createShare: async () => result(),
      copyText: async () => {
        throw new Error("denied");
      },
    });
    choose(
      view.querySelector<HTMLInputElement>('input[type="file"]')!,
      new File(["copy me"], "copy.txt", { type: "text/plain" }),
    );
    await submit(view.querySelector<HTMLFormElement>("form")!);
    const copy = await vi.waitFor(() => {
      const button = Array.from(view.querySelectorAll("button")).find(
        (candidate) => candidate.textContent === "Copy link",
      );
      expect(button).toBeDefined();
      return button;
    });
    copy?.click();
    await vi.waitFor(() =>
      expect(view.querySelector(".copy-status")?.getAttribute("role")).toBe(
        "alert",
      ),
    );
    expect(view.querySelector(".copy-status")?.textContent).toContain(
      "copy it manually",
    );
    expect(view.querySelector<HTMLTextAreaElement>("#generated-share-link")?.value).toBe(
      LINK,
    );
  });

  it.each([
    [new File([], "empty.txt", { type: "text/plain" }), /non-empty/],
    [
      new File([new Uint8Array(64 * 1024)], "oversized.txt", {
        type: "text/plain",
      }),
      /smaller than 64 KB/,
    ],
    [new File(["plain"], "image.png", { type: "image/png" }), /\.txt/],
    [new File([new Uint8Array([0xff])], "bad.txt"), /UTF-8/],
  ])("rejects malformed or oversized input before encryption", async (file, copy) => {
    const createShare = vi.fn<CreateShare>(async () => result());
    const view = root();
    mountLinkOnlyShare(view, {
      openKeyAddress: "0x1111111111111111111111111111111111111111",
      origin: SHARE_ORIGIN,
      createShare,
    });
    choose(view.querySelector<HTMLInputElement>('input[type="file"]')!, file);
    await submit(view.querySelector<HTMLFormElement>("form")!);
    await vi.waitFor(() =>
      expect(view.querySelector(".sender-status")?.textContent).toMatch(copy),
    );
    expect(createShare).not.toHaveBeenCalled();
    expect(view.querySelector(".sender-status")?.getAttribute("role")).toBe(
      "alert",
    );
  });
});

describe("link-only creation and recipient recovery", () => {
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
        now: () => Date.parse("2026-07-23T20:00:00.000Z"),
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
