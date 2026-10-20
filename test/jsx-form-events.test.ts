import { beforeEach, describe, expect, it, vi } from "vitest";

import { installFormEvents } from "../src/artifact/jsx-runtime/form-events.ts";

// Installed once for the document, as runtime.ts does in the frame.
installFormEvents(document);

function page(html: string): HTMLFormElement {
  document.body.innerHTML = html;
  return document.querySelector("form") as HTMLFormElement;
}

const press = (target: Element, key: string, init: KeyboardEventInit = {}): KeyboardEvent => {
  const event = new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(event);
  return event;
};

describe("form submit events in a sandbox that cannot submit forms", () => {
  let submits: SubmitEvent[];
  beforeEach(() => { submits = []; document.body.innerHTML = ""; });
  const watch = (form: HTMLFormElement): void => { form.addEventListener("submit", (event) => { submits.push(event as SubmitEvent); }); };

  it("a click on a submit button fires exactly one submit event, with the submitter, and the browser's own attempt is cancelled", () => {
    const form = page('<form><input name="a"><button>Save</button></form>');
    watch(form);
    const button = form.querySelector("button") as HTMLButtonElement;
    const click = new MouseEvent("click", { bubbles: true, cancelable: true });
    button.dispatchEvent(click);
    expect(submits).toHaveLength(1);
    expect(submits[0]?.submitter).toBe(button);
    expect(submits[0]?.bubbles).toBe(true);
    expect(click.defaultPrevented).toBe(true);
  });

  it("does nothing for a button that is not a submit button, a disabled one, one outside a form, or a click the page cancelled", () => {
    const form = page('<form><button type="button" id="plain">x</button><button disabled id="off">y</button><button id="cancel">z</button></form><button id="outside">o</button>');
    watch(form);
    (document.querySelector("#plain") as HTMLElement).click();
    (document.querySelector("#off") as HTMLElement).click();
    (document.querySelector("#outside") as HTMLElement).click();
    document.querySelector("#cancel")?.addEventListener("click", (event) => event.preventDefault());
    (document.querySelector("#cancel") as HTMLElement).click();
    expect(submits).toHaveLength(0);
  });

  it("honours constraint validation and novalidate", () => {
    const form = page('<form><input required name="a"><button>Save</button></form>');
    watch(form);
    (form.querySelector("button") as HTMLElement).click();
    expect(submits).toHaveLength(0);
    (form.querySelector("input") as HTMLInputElement).value = "x";
    (form.querySelector("button") as HTMLElement).click();
    expect(submits).toHaveLength(1);
    const lax = page('<form novalidate><input required><button>Save</button></form>');
    watch(lax);
    (lax.querySelector("button") as HTMLElement).click();
    expect(submits).toHaveLength(2);
  });

  it("Enter in a text field presses the form's default button; a disabled default button means nothing happens", () => {
    const form = page('<form><input id="a" name="a"><input id="b" name="b"><button id="go">Save</button><button id="two">Other</button></form>');
    watch(form);
    const event = press(form.querySelector("#a") as Element, "Enter");
    expect(event.defaultPrevented).toBe(true);
    expect(submits).toHaveLength(1);
    expect(submits[0]?.submitter?.id).toBe("go");
    (form.querySelector("#go") as HTMLButtonElement).disabled = true;
    press(form.querySelector("#b") as Element, "Enter");
    expect(submits).toHaveLength(1);
  });

  it("Enter with no submit button submits only a form with a single text field", () => {
    const one = page('<form><input name="a"></form>');
    watch(one);
    press(one.querySelector("input") as Element, "Enter");
    expect(submits).toHaveLength(1);
    expect(submits[0]?.submitter).toBeNull();
    const two = page('<form><input name="a"><input name="b"></form>');
    watch(two);
    press(two.querySelector("input") as Element, "Enter");
    expect(submits).toHaveLength(1);
  });

  it("ignores Enter in a textarea or with a modifier or composition, in a handled keydown, and outside a form", () => {
    const form = page('<form><textarea></textarea><input id="a"><button>Save</button></form><input id="loose">');
    watch(form);
    press(form.querySelector("textarea") as Element, "Enter");
    press(form.querySelector("#a") as Element, "Enter", { shiftKey: true });
    press(form.querySelector("#a") as Element, "Enter", { ctrlKey: true });
    press(form.querySelector("#a") as Element, "Enter", { isComposing: true });
    press(document.querySelector("#loose") as Element, "Enter");
    form.querySelector("#a")?.addEventListener("keydown", (event) => event.preventDefault());
    press(form.querySelector("#a") as Element, "Enter");
    press(form.querySelector("#a") as Element, "a");
    expect(submits).toHaveLength(0);
  });

  it("requestSubmit() fires the event too, and refuses a submitter from another form", () => {
    const form = page('<form id="f"><button id="go">Save</button></form><form id="g"><button id="other">x</button></form>');
    watch(form);
    form.requestSubmit();
    form.requestSubmit(form.querySelector("#go") as HTMLButtonElement);
    expect(submits).toHaveLength(2);
    expect(submits[1]?.submitter?.id).toBe("go");
    expect(() => form.requestSubmit(document.querySelector("#other") as HTMLButtonElement)).toThrow(TypeError);
  });

  it("never submits: a form's own submit() is still the browser's (blocked) path and fires no event here", () => {
    const form = page('<form><button>Save</button></form>');
    watch(form);
    const native = vi.spyOn(form, "submit").mockImplementation(() => undefined);
    form.submit();
    expect(native).toHaveBeenCalled();
    expect(submits).toHaveLength(0);
  });
});
