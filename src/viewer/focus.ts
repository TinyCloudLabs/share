/**
 * Every viewer state is a whole-page `root.replaceChildren()` swap, which
 * destroys whatever the user was focused on. Without an explicit focus move a
 * keyboard or screen-reader user lands on a page that announces nothing and
 * has no focused element — including all twelve error states.
 *
 * viewer.html already declares `<div id="viewer" tabindex="-1">` for exactly
 * this. Any other mount point (the sender preview tab, tests) is made
 * programmatically focusable here so no state can regress.
 */
export function focusViewerRoot(root: HTMLElement): void {
  if (!root.hasAttribute("tabindex")) root.tabIndex = -1;
  root.focus();
}

// TC-367 CI PROOF — temporary, reverted immediately
export const __tc367_proof: number = "not a number";
