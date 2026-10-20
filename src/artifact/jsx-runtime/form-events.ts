/**
 * Form submit events inside the sandbox frame.
 *
 * The frame has no `allow-forms` (a page must not be able to submit anywhere), and a
 * sandbox without it refuses a form submission BEFORE the browser fires the `submit`
 * event: a React `<form onSubmit>` never runs. Pages written like every other web page
 * (a submit button, Enter in a text field) would be dead.
 *
 * This module gives them the event without the submission. It cancels the browser's own
 * attempt (nothing navigates, nothing is requested; `form.submit()` stays blocked and
 * `form-action 'none'` stays in force) and dispatches the `submit` event itself, to the
 * page's own handlers, when a person clicks a submit button or presses Enter the way the
 * HTML implicit-submission rules say. It grants no capability: the same page code
 * could already be run from a click handler, and a `submit` event the page does not
 * handle does nothing, as it would not navigate anyway.
 *
 * Runs in the frame (installed by runtime.ts before the page's code), never in the viewer.
 */

type Submitter = HTMLButtonElement | HTMLInputElement;

/** Input types that block implicit submission (the HTML list). */
const TEXT_LIKE = new Set(["text", "search", "url", "tel", "email", "password", "date", "month", "week", "time", "datetime-local", "number"]);

function submitterOf(target: EventTarget | null): Submitter | null {
  if (!(target instanceof Element)) return null;
  const control = target.closest("button, input");
  if (control instanceof HTMLButtonElement) return control.type === "submit" ? control : null;
  if (control instanceof HTMLInputElement) return control.type === "submit" || control.type === "image" ? control : null;
  return null;
}

function newSubmitEvent(submitter: Submitter | null): Event {
  if (typeof SubmitEvent === "function") return new SubmitEvent("submit", { bubbles: true, cancelable: true, submitter });
  const event = new Event("submit", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "submitter", { value: submitter });
  return event;
}

/** The form's constraint validation, then the event. Does nothing a native submit would not have done first. */
function fireSubmit(form: HTMLFormElement, submitter: Submitter | null): void {
  if (!form.isConnected) return;
  const skipValidation = form.noValidate || (submitter !== null && submitter.formNoValidate);
  if (!skipValidation && !form.reportValidity()) return;
  form.dispatchEvent(newSubmitEvent(submitter));
}

/** The form's default button: its first submit button, in tree order. */
function defaultButtonOf(form: HTMLFormElement): Submitter | null {
  for (const element of Array.from(form.elements)) {
    if (element instanceof HTMLButtonElement && element.type === "submit") return element;
    if (element instanceof HTMLInputElement && (element.type === "submit" || element.type === "image")) return element;
  }
  return null;
}

export function installFormEvents(doc: Document): void {
  // Bubble phase on the document: the page's own click and keydown handlers have run, and
  // one that called preventDefault has cancelled the submission, as it would natively.
  doc.addEventListener("click", (event) => {
    const submitter = submitterOf(event.target);
    if (submitter === null || event.defaultPrevented || submitter.disabled || submitter.form === null) return;
    event.preventDefault();
    fireSubmit(submitter.form, submitter);
  });

  doc.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.isComposing || event.defaultPrevented || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey) return;
    const field = event.target;
    if (!(field instanceof HTMLInputElement) || !TEXT_LIKE.has(field.type) || field.form === null) return;
    const form = field.form;
    event.preventDefault();
    const button = defaultButtonOf(form);
    if (button !== null) {
      // A disabled default button means nothing happens.
      if (!button.disabled) button.click();
      return;
    }
    // No button: submit only when this is the form's one field that blocks implicit submission.
    const blocking = Array.from(form.elements).filter((element) => element instanceof HTMLInputElement && TEXT_LIKE.has(element.type));
    if (blocking.length === 1) fireSubmit(form, null);
  });

  // requestSubmit() runs the same algorithm as a click on a submit button.
  HTMLFormElement.prototype.requestSubmit = function requestSubmit(this: HTMLFormElement, submitter?: HTMLElement | null): void {
    if (submitter !== undefined && submitter !== null) {
      if (!(submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) || submitter.form !== this) throw new TypeError("The submitter is not a submit button of this form.");
      fireSubmit(this, submitter);
      return;
    }
    fireSubmit(this, null);
  };
}
