/**
 * Orders: the standing orders the owner's agents follow for each peer
 * (`me/orders/<peer>.md`). Plain text the person writes; saved with a
 * compare-and-swap on the version it was loaded at, so two tabs can't
 * silently overwrite each other. Only the person's own typing is saved.
 */
import { el, status, uid, type ViewContext } from "./dom.js";
import { MAX_ORDERS_BYTES } from "./model.js";
import type { Overview } from "./service.js";
import { startOperation, StoreError, type OrdersFile } from "./store.js";

function failure(error: unknown): string {
  const code = error instanceof StoreError ? error.code : "failed";
  if (code === "changed") return "These orders were changed somewhere else since you opened them. Nothing was saved. Reload them, then make your change again.";
  if (code === "too-large") return "These orders are too long to save. Shorten them and try again.";
  if (code === "denied") return "This session isn't allowed to save orders. Sign out and sign in again. Nothing was saved.";
  if (code === "timeout" || code === "unreachable") return "We couldn't reach your TinyCloud. Nothing was saved. Try again.";
  return "We couldn't save these orders. Nothing was saved. Try again.";
}

export function renderOrders(ctx: ViewContext, overview: Overview): HTMLElement {
  const { doc } = ctx;
  const section = el(doc, "section", "cr-screen");
  section.setAttribute("aria-labelledby", "cr-orders-title");
  const head = el(doc, "div", "cr-screen-head");
  const title = el(doc, "h2", "cr-title", "Orders"); title.id = "cr-orders-title";
  head.append(title);
  section.append(head, el(doc, "p", "cr-muted", "Standing orders tell your agent what it may do for a peer without asking, and what it must ask you about first. Your agent reads them before it acts on anything the peer sends."));
  if (overview.peers.length === 0) {
    const empty = el(doc, "div", "cr-empty");
    empty.append(el(doc, "p", "cr-empty-title", "No peers yet."), el(doc, "p", "cr-muted", "Pairing with a peer is done with the courier command line tool. Once you have a thread with someone, they appear here."));
    section.append(empty);
    return section;
  }

  const selectId = uid("cr-peer");
  const label = el(doc, "label", "tc-label", "Orders for"); label.htmlFor = selectId;
  const select = el(doc, "select", "tc-input cr-select"); select.id = selectId;
  for (const peer of overview.peers) { const option = el(doc, "option", undefined, peer); option.value = peer; select.append(option); }
  const textId = uid("cr-orders");
  const textLabel = el(doc, "label", "tc-label", "Standing orders (plain text or markdown)"); textLabel.htmlFor = textId;
  const text = el(doc, "textarea", "tc-input cr-orders-input"); text.id = textId; text.rows = 16; text.spellcheck = false;
  const info = el(doc, "p", "cr-muted cr-small");
  const save = el(doc, "button", "button button-primary tc-button tc-button--primary", "Save orders"); save.type = "button"; save.disabled = true;
  const reload = el(doc, "button", "button button-secondary tc-button", "Reload"); reload.type = "button"; reload.disabled = true;
  const actions = el(doc, "div", "cr-actions"); actions.append(save, reload);
  const result = el(doc, "div", "cr-result");
  section.append(label, select, textLabel, text, info, actions, result);

  let loaded: OrdersFile | undefined;
  let hadFile = false;
  let busy = false;
  let generation = 0;

  const load = async (operation = startOperation()): Promise<void> => {
    const mine = ++generation;
    const peer = select.value;
    save.disabled = true; reload.disabled = true; text.disabled = true;
    result.replaceChildren(el(doc, "p", "cr-muted", "Loading…"));
    try {
      const file = await ctx.store.readOrders(peer, operation);
      if (mine !== generation) return;
      loaded = file; hadFile = file !== undefined;
      text.value = file?.text ?? "";
      info.textContent = hadFile ? "These are the orders your agent follows for this peer." : "No orders saved yet: your agent follows the built-in default orders for this peer. Write your own and save to replace them.";
      result.replaceChildren();
      text.disabled = false; save.disabled = false; reload.disabled = false;
    } catch (error) {
      if (mine !== generation) return;
      result.replaceChildren(status(doc, "danger", failure(error)));
      reload.disabled = false;
    }
  };

  const write = async (): Promise<void> => {
    if (busy) return;
    const value = text.value;
    if (value.trim() === "") { result.replaceChildren(status(doc, "warning", "Write some orders first. An empty file would leave your agent without any.")); return; }
    if (new TextEncoder().encode(value).byteLength > MAX_ORDERS_BYTES) { result.replaceChildren(status(doc, "warning", failure(new StoreError("too-large")))); return; }
    const operation = startOperation();
    busy = true; save.disabled = true; reload.disabled = true;
    result.replaceChildren(el(doc, "p", "cr-muted", "Saving…"));
    try {
      await ctx.store.writeOrders(select.value, value, loaded?.etag, operation);
      ctx.announcer.say("Orders saved.");
      busy = false;
      await load(operation);
      result.replaceChildren(status(doc, "success", "Saved. Your agent will use these orders from now on."));
    } catch (error) {
      result.replaceChildren(status(doc, "danger", failure(error)));
      ctx.announcer.say("We couldn't save these orders.");
      save.disabled = false; reload.disabled = false;
    } finally {
      busy = false;
    }
  };

  select.addEventListener("change", () => { void load(); });
  reload.addEventListener("click", () => { void load(); });
  save.addEventListener("click", () => { void write(); });
  void load();
  return section;
}
