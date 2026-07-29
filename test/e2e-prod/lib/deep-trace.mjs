/**
 * An init script that narrates the browser primitives a hung sign-in could be
 * waiting on: postMessage round-trips (the OpenKey iframe channel), Workers,
 * WebCrypto, and IndexedDB. Attach with `context.addInitScript(DEEP_TRACE)`.
 *
 * Deliberately verbose. It exists to localise a hang, not to run in a green
 * suite; gate it behind an env flag.
 */
export const DEEP_TRACE = () => {
  const brief = (value) => {
    try {
      const text = typeof value === "string" ? value : JSON.stringify(value);
      return (text ?? String(value)).slice(0, 200);
    } catch {
      return Object.prototype.toString.call(value);
    }
  };

  const originalPost = window.postMessage.bind(window);
  window.postMessage = (...args) => {
    console.log(`[trace] window.postMessage ${brief(args[0])}`);
    return originalPost(...args);
  };

  const framePost = HTMLIFrameElement.prototype;
  const originalContentWindow = Object.getOwnPropertyDescriptor(framePost, "contentWindow");
  if (originalContentWindow !== undefined) {
    Object.defineProperty(framePost, "contentWindow", {
      ...originalContentWindow,
      get() {
        const target = originalContentWindow.get.call(this);
        if (target === null) return target;
        try {
          const raw = target.postMessage.bind(target);
          target.postMessage = (...args) => {
            console.log(`[trace] iframe.postMessage src=${this.src} ${brief(args[0])}`);
            return raw(...args);
          };
        } catch {
          /* cross-origin: cannot instrument, and that is fine */
        }
        return target;
      },
    });
  }

  const originalPortPost = MessagePort.prototype.postMessage;
  MessagePort.prototype.postMessage = function post(...args) {
    console.log(`[trace] port.postMessage ${brief(args[0])}`);
    return originalPortPost.apply(this, args);
  };

  window.addEventListener("message", (event) => console.log(`[trace] message from ${event.origin} ${brief(event.data)}`), true);

  const originalWorker = window.Worker;
  window.Worker = function TracedWorker(url, options) {
    console.log(`[trace] new Worker ${url}`);
    return new originalWorker(url, options);
  };

  for (const name of ["generateKey", "importKey", "sign", "verify", "digest", "deriveBits", "encrypt", "decrypt"]) {
    const original = crypto.subtle[name].bind(crypto.subtle);
    crypto.subtle[name] = async (...args) => {
      const algorithm = typeof args[0] === "string" ? args[0] : args[0]?.name;
      console.log(`[trace] crypto.subtle.${name} ${algorithm}`);
      try {
        return await original(...args);
      } catch (error) {
        console.log(`[trace] crypto.subtle.${name} ${algorithm} REJECTED ${error}`);
        throw error;
      }
    };
  }

  const originalFetch = window.fetch;
  window.fetch = async (...args) => {
    const url = typeof args[0] === "string" ? args[0] : args[0]?.url;
    console.log(`[trace] fetch -> ${url}`);
    try {
      const response = await originalFetch(...args);
      console.log(`[trace] fetch <- ${response.status} ${url}`);
      return response;
    } catch (error) {
      console.log(`[trace] fetch !! ${url} ${error}`);
      throw error;
    }
  };
};
