import { beforeEach, describe, expect, it, vi } from "vitest";
import { appendSaveToTinyCloudAction } from "../src/viewer/present.js";

function viewer(): HTMLElement {
  document.body.innerHTML = '<div id="viewer"><footer class="viewer-footer"><div class="viewer-agent-hint"></div></footer></div>';
  return document.getElementById("viewer")!;
}

describe("TC-500 post-render account import", () => {
  beforeEach(() => { document.body.replaceChildren(); });

  it("starts the account action only after an explicit click and reports success", async () => {
    const root = viewer();
    const save = vi.fn(async () => undefined);
    appendSaveToTinyCloudAction(root, save);

    expect(save).not.toHaveBeenCalled();
    const button = root.querySelector<HTMLButtonElement>(".viewer-save-to-tinycloud")!;
    expect(button.textContent).toBe("Save a private copy");
    button.click();

    await vi.waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(button.textContent).toBe("Saved to Files for you"));
    expect(root.querySelector(".viewer-save-status")?.textContent).toContain("private copy");
  });

  it("is idempotent and leaves retry available after account import fails", async () => {
    const root = viewer();
    const save = vi.fn().mockRejectedValue(new Error("canceled"));
    appendSaveToTinyCloudAction(root, save);
    appendSaveToTinyCloudAction(root, save);
    expect(root.querySelectorAll(".viewer-save-to-tinycloud")).toHaveLength(1);

    const button = root.querySelector<HTMLButtonElement>(".viewer-save-to-tinycloud")!;
    button.click();
    await vi.waitFor(() => expect(root.querySelector("[role=alert]")?.textContent).toContain("couldn't save"));
    expect(button.disabled).toBe(false);
  });
});
