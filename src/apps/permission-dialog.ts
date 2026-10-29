import type { PermissionEntry } from "@tinycloud/web-sdk";

export interface RuntimePermissionDialogOptions {
  readonly appName: string;
  readonly additional: PermissionEntry[];
}

export interface RuntimePermissionDialogResult {
  readonly approved: boolean;
}

/** A DOM-built prompt for the SDK's step-up flow; avoids the SDK modal's untrusted innerHTML sink. */
export function showRuntimePermissionDialog(options: RuntimePermissionDialogOptions): Promise<RuntimePermissionDialogResult> {
  const doc = globalThis.document;
  if (doc === undefined) return Promise.resolve({ approved: false });

  const dialog = doc.createElement("dialog");
  dialog.className = "tc-app-permission-dialog";
  dialog.setAttribute("aria-labelledby", "tc-app-permission-title");
  const heading = doc.createElement("h2");
  heading.id = "tc-app-permission-title";
  heading.textContent = `${options.appName} requests additional access`;
  dialog.append(heading);

  const list = doc.createElement("ul");
  for (const permission of options.additional) {
    const item = doc.createElement("li");
    item.textContent = `${permission.service} · ${permission.space ?? "applications"}/${permission.path} · ${permission.actions.join(", ")}`;
    list.append(item);
  }
  dialog.append(list);

  const actions = doc.createElement("div");
  actions.className = "tc-app-permission-actions";
  const cancel = doc.createElement("button");
  cancel.type = "button";
  cancel.textContent = "Cancel";
  const allow = doc.createElement("button");
  allow.type = "button";
  allow.textContent = "Allow";
  allow.dataset.permissionAllow = "true";
  actions.append(cancel, allow);
  dialog.append(actions);

  const opener = doc.activeElement;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (approved: boolean): void => {
      if (settled) return;
      settled = true;
      dialog.remove();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
      resolve({ approved });
    };
    cancel.addEventListener("click", () => finish(false));
    allow.addEventListener("click", () => finish(true));
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); finish(false); });
    dialog.addEventListener("click", (event) => { if (event.target === dialog) finish(false); });
    doc.body.append(dialog);
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    cancel.focus();
  });
}
