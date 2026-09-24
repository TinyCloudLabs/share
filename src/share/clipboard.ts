/** Copy an authority-bearing link without placing it in the DOM. */
export async function copyWithFallback(value: string): Promise<void> {
  if (navigator.clipboard?.writeText !== undefined) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // A user-gesture copy event remains available in restricted browsers.
    }
  }

  const decoy = document.createElement("span");
  decoy.textContent = " ";
  decoy.setAttribute("aria-hidden", "true");
  Object.assign(decoy.style, { position: "fixed", inset: "0 auto auto -9999px", opacity: "0", pointerEvents: "none", userSelect: "text" });
  let delivered = false;
  const onCopy = (event: Event): void => {
    const clipboardData = (event as ClipboardEvent).clipboardData;
    if (clipboardData === null) return;
    event.preventDefault();
    clipboardData.setData("text/plain", value);
    delivered = true;
  };
  const selection = document.getSelection();
  const preserved: Range[] = [];
  if (selection !== null) for (let index = 0; index < selection.rangeCount; index += 1) preserved.push(selection.getRangeAt(index));
  document.addEventListener("copy", onCopy, true);
  document.body.append(decoy);
  try {
    const range = document.createRange();
    range.selectNodeContents(decoy);
    selection?.removeAllRanges();
    selection?.addRange(range);
    if (!document.execCommand("copy") || !delivered) throw new Error("clipboard unavailable");
  } finally {
    document.removeEventListener("copy", onCopy, true);
    decoy.remove();
    selection?.removeAllRanges();
    for (const range of preserved) selection?.addRange(range);
  }
}

export interface ManualCopyHandle {
  readonly target: HTMLElement;
  readonly select: () => void;
  readonly disarm: () => void;
}

/** Keep a safe decoy selected and substitute the link only in the copy event. */
export function armManualCopy(value: string, onDelivered: () => void): ManualCopyHandle {
  const target = document.createElement("span");
  target.className = "manual-copy-target";
  target.textContent = " ";
  target.setAttribute("aria-hidden", "true");
  const onCopy = (event: Event): void => {
    const clipboardData = (event as ClipboardEvent).clipboardData;
    const selection = document.getSelection();
    if (clipboardData === null || selection === null || selection.rangeCount === 0) return;
    const container = selection.getRangeAt(0).commonAncestorContainer;
    if (container !== target && !target.contains(container)) return;
    event.preventDefault();
    clipboardData.setData("text/plain", value);
    onDelivered();
  };
  document.addEventListener("copy", onCopy, true);
  return {
    target,
    select: () => {
      const selection = document.getSelection();
      if (selection === null) return;
      const range = document.createRange();
      range.selectNodeContents(target);
      selection.removeAllRanges();
      selection.addRange(range);
    },
    disarm: () => {
      document.removeEventListener("copy", onCopy, true);
      document.getSelection()?.removeAllRanges();
      target.remove();
    },
  };
}
