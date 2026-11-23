// src/Contacts.jsx
import React2, { useEffect, useState as useState2, useRef as useRef2 } from "react";
import { kv } from "@tinycloud/app";

// contract/catalog.js
var appId = "xyz.tinycloud.tinyapps.contacts";
var discoveryKey = "xyz.tinycloud.tinyapps.catalog/contacts/entry";
var cardFields = {
  name: "text: display name, e.g. Ada Quill",
  added: "date: local day first added, e.g. 2026-10-06",
  private: 'object: all other card details, e.g. {"tags":["choir"]}'
};
var personField = "slug: person key ending or me for the owner, e.g. ada-quill-a17bc432";
var kinds = {
  person: ["One card for each person.", cardFields],
  me: ["The owner's own card.", cardFields],
  note: ["A sourced profile entry about one person.", {
    person: personField,
    added: "date: day the note was added, e.g. 2026-10-07",
    private: 'object: text and source (required for agents), optional topic label, learned date (defaults to added) and optional replaces (full earlier note key), e.g. {"label":"Voice","text":"Sings alto","source":"Ada Quill at choir rehearsal","learned":"2026-10-07"}'
  }],
  history: ["The card saved before a change.", {
    person: personField,
    action: "text: create, update, restore or import, e.g. update",
    private: 'object: prior holds the complete previous record or null for a new card, e.g. {"prior":null}'
  }]
};
function seedRecords(created, by) {
  const app = "contacts";
  const title = "Contacts";
  const catalog = appId + "/catalog";
  const rows = [{ key: catalog, value: { app, title, about: "Contact cards, notes and earlier versions.", created, by } }];
  for (const [kind, [about, fields2]] of Object.entries(kinds)) {
    const shape = kind === "person" || kind === "me" ? { shape: "subject" } : { shape: "log", per: "time" };
    rows.push({ key: catalog + "/" + kind, value: { app, kind, about, ...shape, v: 1, fields: { ...fields2 }, created, by } });
  }
  rows.push({ key: discoveryKey, value: { v: 1, app, id: appId, title } });
  return rows;
}

// contract/index.js
function check(ok, message) {
  if (!ok) throw new TypeError(message);
}
var matches = (value, pattern) => typeof value === "string" && pattern.test(value);
var nonempty = (value) => typeof value === "string" && value.trim().length > 0;
var object = (value) => value !== null && typeof value === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(value));
var exact = (value, names) => object(value) && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
var clients = ["codex", "claude-code", "opencode", "owner"];
var slugPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*-[a-f0-9]{8}$/;
var subject = (slug) => slug === "me" || matches(slug, slugPattern);
function makeSlug(name) {
  check(nonempty(name), "Expected a name");
  const stem = name.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-/, "").slice(0, 40).replace(/-$/, "") || "person";
  return stem + "-" + crypto.randomUUID().slice(0, 8);
}
function day(value) {
  if (!matches(value, /^\d{4}-\d\d-\d\d$/)) return false;
  const date = /* @__PURE__ */ new Date(value + "T00:00:00Z");
  return Number.isFinite(+date) && date.toISOString().startsWith(value + "T");
}
function stamp(value) {
  return day(value) || matches(value, /^\d{4}-\d\d-\d\dT(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/) && day(value.slice(0, 10));
}
function json(value) {
  if (Array.isArray(value)) {
    for (const element of value) json(element);
  } else if (object(value)) {
    for (const [key, item] of Object.entries(value)) {
      check(/^[a-z0-9_]+$/.test(key), "Invalid field name");
      json(item);
    }
  } else {
    check(value === null || ["boolean", "string"].includes(typeof value) || Number.isFinite(value), "Expected JSON");
  }
}
function equal(a, b) {
  if (a === b) return true;
  if (!(object(a) && object(b) || Array.isArray(a) && Array.isArray(b))) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((k) => Object.hasOwn(b, k) && equal(a[k], b[k]));
}
function containsSeed(value, seed) {
  if (!object(seed)) return value === seed;
  return object(value) && Object.entries(seed).every(([name, meaning]) => Object.hasOwn(value, name) && containsSeed(value[name], meaning));
}
function parseKey(key) {
  check(matches(key, /^[A-Za-z0-9/._~:+@=,-]+$/), "Invalid key character");
  if (key === discoveryKey) return { kind: "discovery" };
  const [root, kind, id, logId, ...extra] = key.split("/");
  check(root === appId && !extra.length, "Invalid app path");
  if (kind === "catalog" && logId === void 0 && (id === void 0 || ["person", "me", "note", "history"].includes(id))) return { kind };
  if (logId === void 0 && (kind === "me" && id === "me" || kind === "person" && matches(id, slugPattern))) {
    return { kind, person: id };
  }
  const log = /^(\d{4}-\d\d-\d\d)T(?:[01]\d|2[0-3])[0-5]\d-(.+)$/.exec(logId ?? "");
  check(["note", "history"].includes(kind) && log && day(log[1]) && log[1].startsWith(id + "-") && id.length === 7, "Invalid log key");
  const person = subject(log[2]) ? log[2] : log[2].replace(/-(?:[2-9]|[1-9]\d+)$/, "");
  check(subject(person), "Invalid log subject");
  return { kind, person };
}
function card(record2) {
  envelope(record2);
  const d = record2.data;
  check(exact(d, ["name", "added", "private"]) && nonempty(d.name) && day(d.added) && object(d.private), "Invalid card fields");
}
function envelope(record2) {
  check(exact(record2, ["v", "at", "data", "by"]) && record2.v === 1 && stamp(record2.at) && clients.includes(record2.by) && object(record2.data), "Invalid record envelope");
}
function validate({ key, value }) {
  const { kind, person } = parseKey(key);
  json(value);
  if (kind === "catalog" || kind === "discovery") {
    if (kind === "catalog") check(day(value.created) && clients.includes(value.by), "Invalid catalog attribution");
    const seed = seedRecords(value.created, value.by).find((row) => row.key === key);
    check(kind === "discovery" ? equal(value, seed.value) : containsSeed(value, seed.value), "Unexpected seed fields or meanings");
  } else if (kind === "person" || kind === "me") {
    card(value);
  } else {
    envelope(value);
    const d = value.data;
    check(d.person === person && object(d.private), "Invalid log subject or private fields");
    if (kind === "note") {
      check(exact(d, ["person", "added", "private"]) && day(d.added) && nonempty(d.private.text) && (value.by === "owner" && !Object.hasOwn(d.private, "source") || nonempty(d.private.source)), "Expected note text and source");
      if (Object.hasOwn(d.private, "label")) check(nonempty(d.private.label), "Expected a topic label");
      if (Object.hasOwn(d.private, "learned")) check(day(d.private.learned), "Expected a learned date");
      if (Object.hasOwn(d.private, "replaces")) {
        const prior = parseKey(d.private.replaces);
        check(
          prior.kind === "note" && prior.person === person && d.private.replaces !== key,
          "A correction must name another note about the same person"
        );
      }
    } else {
      check(exact(d, ["person", "action", "private"]) && exact(d.private, ["prior"]) && ["create", "update", "import", "restore"].includes(d.action), "Invalid history");
      if (d.private.prior === null) check(["create", "import"].includes(d.action), "Missing prior card");
      else {
        check(d.action !== "create", "Create requires an absent card");
        card(d.private.prior);
      }
    }
  }
  return true;
}
function record(key, data, at, by) {
  const row = { key, value: { v: 1, at, data, by } };
  validate(row);
  const copy = structuredClone(row);
  if (parseKey(key).kind === "note") copy.value.data.private.learned ??= data.added;
  return copy;
}
function currentNotes(rows) {
  const parents = /* @__PURE__ */ new Map();
  const replaced = /* @__PURE__ */ new Set();
  for (const { key, value } of rows) {
    const parent = value.data.private.replaces;
    parents.set(key, parent);
    if (parent) replaced.add(parent);
  }
  const roots = /* @__PURE__ */ new Map();
  const loops = /* @__PURE__ */ new Set();
  function rootOf(key) {
    const path = /* @__PURE__ */ new Set();
    while (parents.get(key) && !roots.has(key)) {
      if (path.has(key)) {
        loops.add(key);
        break;
      }
      path.add(key);
      key = parents.get(key);
    }
    const root = roots.get(key) ?? key;
    for (const member of path) roots.set(member, root);
    return root;
  }
  const latest = /* @__PURE__ */ new Map();
  for (const row of rows) {
    const root = rootOf(row.key);
    if (replaced.has(row.key) && !loops.has(root)) continue;
    const previous = latest.get(root);
    if (!previous || row.key.localeCompare(previous.key, "en", { numeric: true }) > 0) latest.set(root, row);
  }
  return [...latest.values()];
}
function validateChange(current, writes) {
  check(Array.isArray(writes) && writes.length === 2 && parseKey(writes[0].key).kind === "history", "Write history first");
  const [history, next] = writes;
  writes.forEach(validate);
  const target = parseKey(next.key);
  check(["person", "me"].includes(target.kind) && target.person === history.value.data.person, "Wrong card");
  if (current !== null) validate({ key: next.key, value: current });
  check(equal(history.value.data.private.prior, current) && next.value.at === history.value.at && next.value.by === history.value.by, "History must capture this change");
  return true;
}
function change({ key, current, data, action, historyKey, at, by }) {
  const person = parseKey(key).person;
  const writes = [
    record(historyKey, { person, action, private: { prior: current } }, at, by),
    record(key, data, at, by)
  ];
  validateChange(current, writes);
  return writes;
}
function restore(options, saved) {
  validate(saved);
  check(parseKey(saved.key).kind === "history" && saved.value.data.person === parseKey(options.key).person && saved.value.data.private.prior !== null && options.current !== null, "Expected a prior version of this card");
  return change({ ...options, data: saved.value.data.private.prior.data, action: "restore" });
}

// app/copy.js
var words = {
  title: "Contacts",
  purpose: "Keep the people you know, and what you learn about them, in one place.",
  privacy: "Your contacts are kept in your own TinyCloud space. Apps can open them only with your approval.",
  people: "People",
  search: "Search people",
  add: "Add person",
  me: "Me",
  own: "My card",
  menu: "Options",
  about: "About this app",
  location: "Saved in your TinyCloud as",
  import: "Import",
  exportAll: "Export all",
  exportOne: "Export this person",
  pick: "Choose a vCard file (.vcf)",
  preview: "Review your import",
  newCard: "New person",
  match: "Matches someone in your contacts",
  skipCard: "Skip this card",
  addMatch: "Add as a new person",
  importSelected: "Import selected",
  matchInFile: "Matches an earlier card in this file",
  oneUnreadable: "card couldn't be read",
  manyUnreadable: "cards couldn't be read",
  fileLimit: "This file has too much information. Try a smaller vCard file.",
  waitingToImport: "Your space is busy. Trying again shortly.",
  noCards: "No named contact cards were found in this file.",
  unreadable: "This file couldn't be read. Check that it's a vCard (.vcf) file.",
  progress: "Cards checked",
  summary: "Import complete",
  added: "Added",
  skipped: "Skipped",
  failed: "Failed",
  done: "Done",
  includeMe: "Include my card",
  exportNotice: "The export file is not protected. Anyone who has it can read it.",
  saveFile: "Save file",
  copyInstead: "Copy the text instead",
  fileReady: "The file is ready. Look for the Save button in the bar above the app.",
  fileWaiting: "Save or close the file in the bar above first.",
  noFileOffer: "Files can't be saved from here. Copy the text instead.",
  fileError: "This file couldn't be saved. Copy the text instead.",
  fileTooLarge: "This file is too large to save. Copy the text instead.",
  exportHelp: "Select the text and copy it. Then save it as contacts.vcf in a plain text editor.",
  selectText: "Select all text",
  vcardText: "vCard text",
  back: "Back to people",
  edit: "Edit card",
  createMe: "Create my card",
  emptyMe: "Add your own details here.",
  empty: "Your address book starts here",
  emptyText: "Add someone you want to remember.",
  noMatch: "No matching people",
  choose: "Open a card",
  chooseText: "Choose someone from your people to see their details and notes.",
  profile: "Profile",
  history: "History",
  noHistory: "No earlier versions yet.",
  noDetails: "No details added yet.",
  restore: "Restore this version",
  agent: "Agent",
  owner: "You",
  name: "Name",
  save: "Save card",
  cancel: "Cancel",
  skippedEntry: "entry couldn't be shown",
  skippedEntries: "entries couldn't be shown",
  loading: "Opening your address book\u2026",
  saving: "Saving\u2026",
  retry: "Reload contacts",
  entries: "Entries",
  addEntry: "Add entry",
  correct: "Correct",
  earlier: "Earlier versions",
  topic: "Topic",
  text: "Entry",
  source: "Source",
  learned: "Date learned",
  from: "Learned from:",
  saveEntry: "Save entry",
  emptyEntries: "Keep what you learn about this person here.",
  untitled: "Note",
  actions: {
    create: "Created",
    update: "Edited",
    restore: "Restored",
    import: "Imported"
  },
  fields: {
    organization: "Organization",
    role: "Role",
    blurb: "About",
    emails: "Emails",
    phones: "Phone numbers",
    addresses: "Addresses",
    birthday: "Birthday",
    relationship: "Relationship",
    tags: "Tags",
    links: "Links"
  },
  errors: {
    PERMISSION_DENIED: "Contacts needs your approval to open or change these details.",
    TOO_LARGE: "There is too much information to open or save at once.",
    BUSY: "Your space is busy. Try again shortly.",
    TIMEOUT: "Your space took too long to answer. Reload to check what was saved.",
    NOT_CONNECTED: "Your connection ended. Close Contacts and open it to connect.",
    PRECONDITION_FAILED: "This card changed. Reload to see the latest version.",
    NOT_FOUND: "This couldn't be found. It may have been removed.",
    BAD_REQUEST: "These details couldn't be read.",
    SQL_ERROR: "Something went wrong. Try again.",
    INTERNAL: "Something went wrong. Try again."
  }
};

// src/store.js
var author = (by) => by === "owner" ? words.owner : words.agent + " \xB7 " + by;
var errorText = (code) => words.errors[code] || words.errors.INTERNAL;
function people(rows, search = "") {
  return rows.filter(
    (row) => parseKey(row.key).kind === "person" && [
      row.value.data.name,
      ...Object.values(row.value.data.private).flat(Infinity)
    ].join(" ").toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())
  ).sort((a, b) => a.value.data.name.localeCompare(b.value.data.name));
}
function fail(code) {
  throw Object.assign(new Error(code), { code });
}
function result(reply) {
  if (!reply.ok) fail(reply.error.code);
  return reply;
}
function localDay(d) {
  return [d.getFullYear(), d.getMonth() + 1, d.getDate()].map((x) => String(x).padStart(2, "0")).join("-");
}
var sendOnce = (call) => call();
function contacts(kv2) {
  const relative = (key) => key.slice(appId.length + 1);
  const changedRows = /* @__PURE__ */ new Map();
  const localHistory = /* @__PURE__ */ new Map();
  const unreadable = /* @__PURE__ */ new Set();
  const waiting = [];
  let active = 0;
  async function read(call) {
    if (active === 3) await new Promise((resolve) => waiting.push(resolve));
    else active++;
    try {
      return await call();
    } finally {
      const next = waiting.shift();
      if (next) next();
      else active--;
    }
  }
  async function get(key, tolerant = false, send = sendOnce) {
    const reply = await send(() => read(() => kv2.get(relative(key))));
    if (!reply.ok && reply.error.code === "NOT_FOUND") return null;
    const { bytes } = result(reply);
    try {
      const value = JSON.parse(new TextDecoder().decode(bytes));
      validate({ key, value });
      unreadable.delete(key);
      return value;
    } catch (error) {
      if (!tolerant) throw error;
      unreadable.add(key);
      return void 0;
    }
  }
  async function put(row, create, send = sendOnce) {
    const opts = { contentType: "application/json" };
    if (create) opts.ifNoneMatch = true;
    const body = JSON.stringify(row.value);
    const reply = await send(() => kv2.put(relative(row.key), body, opts));
    if (!reply.ok && reply.error.code !== "TIMEOUT") result(reply);
    const actual = await get(row.key, false, send);
    if (JSON.stringify(actual) !== JSON.stringify(row.value))
      fail(reply.ok ? "PRECONDITION_FAILED" : "TIMEOUT");
    const kind = parseKey(row.key).kind;
    if (kind !== "catalog") {
      changedRows.set(row.key, row);
      if (kind === "history") localHistory.set(row.key, row);
    }
  }
  async function folderRows(folder, person) {
    const listing = result(await read(() => kv2.list(folder)));
    if (listing.truncated) fail("TOO_LARGE");
    const keys = [];
    for (const path of listing.keys) {
      const key = appId + "/" + path;
      try {
        if (!path.startsWith(folder)) throw new TypeError();
        const parsed = parseKey(key);
        if (!person || parsed.person === person) keys.push(key);
      } catch {
        unreadable.add(key);
      }
    }
    const rows = [];
    for (let start = 0; start < keys.length; start += 3) {
      const group = keys.slice(start, start + 3);
      const values = await Promise.all(group.map((key) => get(key, true)));
      for (const [index, value] of values.entries()) {
        if (value) rows.push({ key: group[index], value });
      }
    }
    return rows;
  }
  async function load(historyKey = null) {
    unreadable.clear();
    for (const row of seedRecords(localDay(/* @__PURE__ */ new Date()), "owner")) {
      if (row.key === discoveryKey || await get(row.key, true) !== null)
        continue;
      try {
        await put(row, true);
      } catch (e) {
        if (e.code !== "PRECONDITION_FAILED" || await get(row.key, true) === null)
          throw e;
      }
    }
    const rows = (await folderRows("person/")).concat(await folderRows("note/"));
    const key = appId + "/me/me", value = await get(key, true);
    if (value) rows.push({ key, value });
    const versions = historyKey ? await history(historyKey) : [...localHistory.values()];
    return rows.concat(versions);
  }
  function history(key) {
    return folderRows("history/", parseKey(key).person);
  }
  function changes() {
    const rows = [...changedRows.values()];
    changedRows.clear();
    return rows;
  }
  async function save({ key, expected, name, fields: fields2, saved }, createAction = "create", send = sendOnce) {
    if (!key) {
      do {
        key = appId + "/person/" + makeSlug(name);
      } while (await get(key, false, send));
    }
    const current = await get(key, false, send);
    if (JSON.stringify(current) !== JSON.stringify(expected ?? null))
      fail("PRECONDITION_FAILED");
    const now = /* @__PURE__ */ new Date(), day2 = localDay(now);
    const at = now.toISOString().replace(/\.\d{3}Z$/, "Z");
    const clock = [now.getHours(), now.getMinutes()].map((x) => String(x).padStart(2, "0")).join("");
    const stem = appId + "/history/" + day2.slice(0, 7) + "/" + day2 + "T" + clock + "-" + parseKey(key).person;
    for (let i = 1; ; i++) {
      const options = {
        key,
        current,
        historyKey: stem + (i === 1 ? "" : "-" + i),
        at,
        by: "owner"
      };
      const writes = saved ? restore(options, saved) : change({
        ...options,
        action: current ? "update" : createAction,
        data: {
          name: name === current?.data.name ? name : name.trim(),
          added: current?.data.added || day2,
          private: { ...current?.data.private, ...fields2 }
        }
      });
      try {
        await put(writes[0], true, send);
      } catch (e) {
        if (e.code === "PRECONDITION_FAILED") continue;
        throw e;
      }
      if (JSON.stringify(await get(key, false, send)) !== JSON.stringify(current))
        fail("PRECONDITION_FAILED");
      await put(writes[1], !current, send);
      return key;
    }
  }
  async function append(key, fields2) {
    if (!await get(key)) fail("NOT_FOUND");
    if (fields2.replaces && !await get(fields2.replaces)) fail("NOT_FOUND");
    const person = parseKey(key).person;
    const now = /* @__PURE__ */ new Date(), added = localDay(now);
    const clock = [now.getHours(), now.getMinutes()].map((x) => String(x).padStart(2, "0")).join("");
    const stem = appId + "/note/" + added.slice(0, 7) + "/" + added + "T" + clock + "-" + person;
    for (let i = 1; ; i++) {
      const noteKey = stem + (i === 1 ? "" : "-" + i);
      if (noteKey === fields2.replaces) continue;
      const row = record(
        noteKey,
        { person, added, private: fields2 },
        now.toISOString().split(".")[0] + "Z",
        "owner"
      );
      try {
        await put(row, true);
        return key;
      } catch (e) {
        if (e.code !== "PRECONDITION_FAILED") throw e;
      }
    }
  }
  function importCard({ name, private: fields2 }, send) {
    return save({ name, fields: fields2 }, "import", send);
  }
  return {
    load,
    save,
    append,
    history,
    changes,
    importCard,
    skipped: () => unreadable.size
  };
}

// src/Transfer.jsx
import React, { useRef, useState } from "react";
import * as tc from "@tinycloud/app";

// contract/vcard.js
var fields = new Map(
  Object.entries({
    EMAIL: "emails",
    TEL: "phones",
    ADR: "addresses",
    ORG: "organization",
    TITLE: "role",
    BDAY: "birthday",
    URL: "links",
    NOTE: "blurb",
    CATEGORIES: "tags"
  })
);
var lists = /* @__PURE__ */ new Set(["EMAIL", "TEL", "ADR", "URL", "CATEGORIES"]);
var maxRawVcardBytes = 50 * 1024 * 1024;
var maxVcardBytes = 5 * 1024 * 1024;
var maxCards = 2e3;
var maxProperties = 4096;
var maxPhysicalLines = 16384;
var quotedPrintable = /;ENCODING="?QUOTED-PRINTABLE"?(?:;|$)/i;
function limit(ok) {
  if (!ok) throw new RangeError("vCard limit exceeded");
}
function utf8Bytes(text) {
  if (!/[^\x00-\x7f]/.test(text)) return text.length;
  let size = 0;
  for (const char of text) {
    const cp = char.codePointAt(0);
    size += cp < 128 ? 1 : cp < 2048 ? 2 : cp < 65536 ? 3 : 4;
  }
  return size;
}
function* unfold(text) {
  const ends = /\r\n|[\r\n]/g;
  let start = text.startsWith("\uFEFF") ? 1 : 0;
  let pieces = [];
  let qp = false;
  let soft = false;
  let colon = -1;
  let length = 0;
  let quoted = false;
  let fileLines = 0;
  let keptBytes = start ? 3 : 0;
  let skipMedia = false;
  const media = /(?:[a-z0-9-]+\.)?(?:photo|logo|sound)(?=[;:])/iy;
  while (start < text.length) {
    const lineStart = start;
    const end = ends.exec(text);
    start = end ? ends.lastIndex : text.length;
    const first = text[lineStart];
    const folded = first === " " || first === "	";
    if (!soft && !folded) {
      if (pieces.length) {
        yield { line: pieces.join(""), physical: pieces.length, colon };
        pieces = [];
        qp = false;
        colon = -1;
        length = 0;
        quoted = false;
      }
      media.lastIndex = lineStart;
      skipMedia = media.test(text);
    }
    if (skipMedia) continue;
    let next = text.slice(lineStart, end?.index ?? text.length);
    keptBytes += utf8Bytes(next) + (end?.[0].length ?? 0);
    limit(keptBytes <= maxVcardBytes && ++fileLines <= 131072);
    limit(pieces.length < maxPhysicalLines);
    if (soft) pieces[pieces.length - 1] = pieces.at(-1).slice(0, -1);
    if (folded) next = next.slice(1);
    pieces.push(next);
    if (colon < 0) {
      for (let i = 0; i < next.length; i++) {
        if (next[i] === '"') quoted = !quoted;
        else if (next[i] === ":" && !quoted) {
          const spec = pieces.length === 1 ? next.slice(0, i) : pieces.slice(0, -1).join("") + next.slice(0, i);
          qp = quotedPrintable.test(spec);
          colon = length + i;
          break;
        }
      }
    }
    length += next.length;
    soft = qp && next.endsWith("=");
  }
  if (pieces.length)
    yield { line: pieces.join(""), physical: pieces.length, colon };
}
var decoder = new TextDecoder();
function decodeBytes(value) {
  return value.replace(/(?:=[\da-f]{2})+/gi, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++)
      bytes[i] = parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    return decoder.decode(bytes);
  });
}
function parts(value, separator) {
  const result2 = [];
  let part = "";
  for (let i = 0; i < value.length; i++) {
    if (value[i] === "\\" && i + 1 < value.length) {
      const char = value[++i];
      part += char.toLowerCase() === "n" ? "\n" : char;
    } else if (value[i] === separator) {
      result2.push(part);
      part = "";
    } else {
      part += value[i];
    }
  }
  return [...result2, part];
}
function parseVcardFile(text) {
  limit(text.length <= maxRawVcardBytes && utf8Bytes(text) <= maxRawVcardBytes);
  const cards = [];
  let card2, version, fallback, malformed, properties, physicalLines;
  let started = 0;
  let unreadable = 0;
  for (const { line, physical, colon } of unfold(text)) {
    if (/^BEGIN:VCARD$/i.test(line)) {
      limit(++started <= maxCards);
      if (card2) unreadable++;
      card2 = { name: "", private: {} };
      version = fallback = "";
      malformed = false;
      properties = 0;
      physicalLines = physical;
      continue;
    }
    if (!card2) continue;
    physicalLines += physical;
    limit(physicalLines <= maxPhysicalLines);
    if (/^END:VCARD$/i.test(line)) {
      if (!card2.name) card2.name = fallback;
      if (!malformed && card2.name.trim() && ["3.0", "4.0"].includes(version))
        cards.push(card2);
      else unreadable++;
      card2 = null;
      continue;
    }
    if (!line) continue;
    limit(++properties <= maxProperties);
    if (colon < 1) {
      malformed = true;
      continue;
    }
    const spec = line.slice(0, colon);
    const rawValue = line.slice(colon + 1);
    const groupName = spec.split(";", 1)[0];
    const prop = groupName.slice(groupName.lastIndexOf(".") + 1).toUpperCase();
    const extension = /^X-TINYCLOUD-(\w+)-JSON$/.exec(prop);
    if (extension && fields.has(extension[1])) {
      try {
        card2.private[fields.get(extension[1])] = JSON.parse(parts(rawValue)[0]);
      } catch {
      }
      continue;
    }
    const field = fields.get(prop);
    if (!field && !["VERSION", "FN", "N"].includes(prop)) continue;
    const value = quotedPrintable.test(spec) ? decodeBytes(rawValue) : rawValue;
    if (prop === "VERSION") {
      if (version) malformed = true;
      version = value.trim();
    } else if (prop === "FN") {
      if (!card2.name) {
        const name = parts(value)[0];
        if (name.trim()) card2.name = name;
      }
    } else if (prop === "N") {
      const [family, given, middle, prefix, suffix] = parts(value, ";");
      fallback = [prefix, given, middle, family, suffix].filter(Boolean).join(" ");
    } else {
      let values;
      if (prop === "ADR" || prop === "ORG") {
        values = [parts(value, ";").filter(Boolean).join(", ")];
      } else if (prop === "CATEGORIES") {
        values = parts(value, ",");
      } else if (prop === "BDAY" && /;X-TINYCLOUD-DATE=EXTENDED(?:;|$)/i.test(spec)) {
        values = [value.replace(/^(\d{4})(\d\d)(\d\d)$/, "$1-$2-$3")];
      } else if (prop === "URL" || prop === "TEL" && /;VALUE=uri(?:;|$)/i.test(spec)) {
        values = [value];
      } else {
        values = parts(value);
      }
      const shape = /;X-TINYCLOUD-SHAPE=(TEXT|LIST|EMPTY)(?:;|$)/i.exec(spec)?.[1].toUpperCase();
      if (shape === "EMPTY") values = [];
      const prior = card2.private[field];
      if (prior !== void 0 || shape === "LIST" || shape === "EMPTY" || lists.has(prop) && shape !== "TEXT" || values.length > 1) {
        const list = Array.isArray(prior) ? prior : prior == null ? [] : [prior];
        for (const item of values) list.push(item);
        card2.private[field] = list;
      } else {
        card2.private[field] = values[0];
      }
    }
  }
  if (card2) unreadable++;
  return { cards, unreadable };
}
var escape = (value) => value.replace(/\\/g, "\\\\").replace(/\r\n|\r|\n/g, "\\n").replace(/[,;]/g, (char) => "\\" + char);
function fold(line) {
  const lines = [];
  let current = "", size = 0;
  for (const char of line) {
    const cp = char.codePointAt(0);
    const bytes = cp < 128 ? 1 : cp < 2048 ? 2 : cp < 65536 ? 3 : 4;
    if (size + bytes > 75) {
      lines.push(current);
      current = " ";
      size = 1;
    }
    current += char;
    size += bytes;
  }
  return [...lines, current].join("\r\n");
}
function serializeVcard({ name, private: details }) {
  const lines = ["BEGIN:VCARD", "VERSION:4.0", "FN:" + escape(name)];
  for (const [prop, field] of fields) {
    const value = details[field];
    if (value === void 0) continue;
    const array = Array.isArray(value);
    let values = array ? value : [value];
    if (!values.every(
      (item) => typeof item === "string" && !item.includes("\r") && !(prop === "URL" && item.includes("\n"))
    )) {
      lines.push(
        "X-TINYCLOUD-" + prop + "-JSON:" + escape(JSON.stringify(value))
      );
      continue;
    }
    let spec = prop;
    if (!values.length) {
      spec += ";X-TINYCLOUD-SHAPE=EMPTY";
      values = [""];
    } else if (array !== lists.has(prop)) {
      spec += ";X-TINYCLOUD-SHAPE=" + (array ? "LIST" : "TEXT");
    }
    if (prop === "CATEGORIES") {
      lines.push(spec + ":" + values.map(escape).join(","));
      continue;
    }
    for (const item of values) {
      if (prop === "ADR") lines.push(spec + ":;;" + escape(item) + ";;;;");
      else if (prop === "URL") lines.push(spec + ":" + item);
      else if (prop === "TEL" && /^tel:[^\s\\]+$/i.test(item))
        lines.push(spec + ";VALUE=uri:" + item);
      else if (prop === "BDAY" && /^\d{4}-\d\d-\d\d$/.test(item))
        lines.push(
          spec + ";X-TINYCLOUD-DATE=EXTENDED:" + item.replaceAll("-", "")
        );
      else if (prop === "BDAY" && !/^(?:\d{4}(?:\d{4})?|--\d\d(?:\d\d)?|---\d\d)$/.test(item))
        lines.push(spec + ";VALUE=text:" + escape(item));
      else if (prop === "TEL") lines.push(spec + ";VALUE=text:" + escape(item));
      else lines.push(spec + ":" + escape(item));
    }
  }
  return [...lines.map(fold), "END:VCARD", ""].join("\r\n");
}

// src/import.js
function matchKeys(card2) {
  const name = card2.name.trim().normalize().toLowerCase().replace(/\s+/g, " ");
  const keys = [];
  for (const field of ["emails", "phones"]) {
    const details = card2.private[field];
    for (const detail of Array.isArray(details) ? details : [details]) {
      if (typeof detail !== "string") continue;
      const text = detail.trim().toLowerCase();
      const value = field === "phones" ? text.replace(/^tel:/, "").replace(/[\s().-]/g, "") : text;
      if (value) keys.push(JSON.stringify([name, field, value]));
    }
  }
  return keys;
}
function previewImport(candidates, peopleRows) {
  const known = new Set(peopleRows.flatMap((row) => matchKeys(row.value.data)));
  const earlier = /* @__PURE__ */ new Set();
  return candidates.map((card2) => {
    const keys = matchKeys(card2);
    const matchInFile = keys.some((key) => earlier.has(key));
    const match = matchInFile || keys.some((key) => known.has(key));
    for (const key of keys) earlier.add(key);
    return { card: card2, match, matchInFile, selected: !match };
  });
}
async function importSelected(book2, entries, progress = () => {
}) {
  const selected = entries.filter((entry) => entry.selected);
  const summary = {
    added: 0,
    skipped: entries.length - selected.length,
    failed: []
  };
  const failures = [];
  let next = 0, done = 0, waiting = 0;
  const update = () => progress(done, selected.length, waiting > 0);
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  async function send(call) {
    for (let attempt = 0; ; attempt++) {
      const reply = await call();
      if (reply.ok || reply.error.code !== "BUSY" || attempt === 3) return reply;
      waiting++;
      update();
      await pause(100 * 2 ** attempt);
      waiting--;
      update();
    }
  }
  async function worker() {
    while (next < selected.length) {
      const index = next++;
      const { card: card2 } = selected[index];
      try {
        await book2.importCard(card2, send);
        summary.added++;
      } catch (error) {
        failures[index] = { name: card2.name, code: error.code || "INTERNAL" };
      }
      done++;
      update();
      if (next < selected.length) await pause(0);
    }
  }
  update();
  await Promise.all(
    Array.from({ length: Math.min(3, selected.length) }, worker)
  );
  summary.failed = failures.filter(Boolean);
  return summary;
}

// src/Transfer.jsx
function ImportCards({ rows, book: book2, close }) {
  const [entries, setEntries] = useState([]);
  const [unreadable, setUnreadable] = useState(0);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(null);
  const [result2, setResult] = useState(null);
  const running = useRef(false);
  async function read(file2) {
    if (!file2) return;
    setReading(true);
    setError("");
    setUnreadable(0);
    try {
      if (file2.size > maxRawVcardBytes) {
        setError(words.fileLimit);
        return;
      }
      const parsed = parseVcardFile(await file2.text());
      setUnreadable(parsed.unreadable);
      setEntries(previewImport(parsed.cards, people(rows)));
      if (!parsed.cards.length && !parsed.unreadable) setError(words.noCards);
    } catch (error2) {
      setError(error2 instanceof RangeError ? words.fileLimit : words.unreadable);
    } finally {
      setReading(false);
    }
  }
  function updateCard(index, choice) {
    setEntries(
      (current) => current.map((entry, i) => i === index ? { ...entry, ...choice } : entry)
    );
  }
  async function save() {
    if (running.current) return;
    running.current = true;
    setResult(
      await importSelected(
        book2,
        entries,
        (done, total, waiting) => setProgress({ done, total, waiting })
      )
    );
    setProgress(null);
  }
  return <section className="transfer">
      <h2>{result2 ? words.summary : entries.length ? words.preview : words.import}</h2>
      {unreadable > 0 && <p role="status">
          {unreadable} {unreadable === 1 ? words.oneUnreadable : words.manyUnreadable}
        </p>}
      {result2 ? <>
          <dl>
            {["added", "skipped", "failed"].map((key) => <div key={key}>
                <dt>{words[key]}</dt>
                <dd>{key === "failed" ? result2.failed.length : result2[key]}</dd>
              </div>)}
          </dl>
          {result2.failed.map(({ name, code }, i) => <p key={i}>
              {name} · {errorText(code)}
            </p>)}
          <button onClick={() => close(true)}>{words.done}</button>
        </> : <>
          {!entries.length ? <label>
              {words.pick}
              <input
    type="file"
    accept=".vcf,text/vcard,text/x-vcard"
    disabled={reading}
    onChange={(e) => read(e.target.files[0])}
  />
            </label> : <div className="choices">
              {entries.map((entry, i) => <div className="previewCard" key={i}>
                  <label className="choice">
                    <input
    type="checkbox"
    aria-label={words.import + " " + entry.card.name}
    checked={entry.selected}
    disabled={!!progress || entry.match && !entry.addAsNew}
    onChange={(e) => updateCard(i, { selected: e.target.checked })}
  />
                    <span>
                      <strong>{entry.card.name}</strong>
                      {!entry.match && <small>{words.newCard}</small>}
                    </span>
                  </label>
                  {entry.match && <fieldset className="matchChoice" disabled={!!progress}>
                      <legend>
                        {entry.matchInFile ? words.matchInFile : words.match}
                      </legend>
                      {[false, true].map((add) => <label key={String(add)}>
                          <input
    type="radio"
    name={"match-" + i}
    checked={Boolean(entry.addAsNew) === add}
    onChange={() => updateCard(i, { addAsNew: add, selected: add })}
  />
                          {add ? words.addMatch : words.skipCard}
                        </label>)}
                    </fieldset>}
                </div>)}
            </div>}
          {error && <p role="alert">{error}</p>}
          {progress && <p role="status">
              {words.progress} · {progress.done} / {progress.total}
              {progress.waiting && " \xB7 " + words.waitingToImport}
            </p>}
          <div className="actions">
            {!!entries.length && <button className="primary" disabled={!!progress} onClick={save}>
                {words.importSelected}
              </button>}
            <button
    disabled={reading || !!progress}
    onClick={() => close(false)}
  >
              {words.cancel}
            </button>
          </div>
        </>}
    </section>;
}
function ExportCards({ cards, own, single, close }) {
  const [includeMe, setIncludeMe] = useState(false);
  const available = typeof tc.file?.save === "function";
  const [copy, setCopy] = useState(!available);
  const [message, setMessage] = useState(available ? "" : words.noFileOffer);
  const [offered, setOffered] = useState(false);
  const [pending, setPending] = useState(false);
  const field = useRef(null);
  const selected = includeMe && own ? [...cards, own] : cards;
  const output = selected.map((row) => serializeVcard(row.value.data)).join("");
  async function offer() {
    setPending(true);
    try {
      const name = "contacts-" + localDay(/* @__PURE__ */ new Date()) + ".vcf";
      const reply = await tc.file.save(name, output, { type: "text/vcard" });
      if (reply.ok) {
        setOffered(true);
        setMessage(words.fileReady);
      } else if (reply.error?.code === "BUSY") setMessage(words.fileWaiting);
      else {
        setMessage(
          reply.error?.code === "TOO_LARGE" ? words.fileTooLarge : words.fileError
        );
        setCopy(true);
      }
    } catch {
      setMessage(words.fileError);
      setCopy(true);
    } finally {
      setPending(false);
    }
  }
  return <section className="transfer">
      <h2>{single ? words.exportOne : words.exportAll}</h2>
      <p>{words.exportNotice}</p>
      {own && <label className="choice">
          <input
    type="checkbox"
    checked={includeMe}
    disabled={pending || offered}
    onChange={(e) => {
      setIncludeMe(e.target.checked);
      setMessage(available ? "" : words.noFileOffer);
    }}
  />
          {words.includeMe}
        </label>}
      {message && <p role="status">{message}</p>}
      {copy && <>
          <p>{words.exportHelp}</p>
          <label>
            {words.vcardText}
            <textarea ref={field} readOnly value={output} rows={6} />
          </label>
        </>}
      <div className="actions">
        {copy ? <button
    className="primary"
    disabled={!output}
    onClick={() => {
      field.current.focus();
      field.current.select();
    }}
  >
            {words.selectText}
          </button> : <>
            <button
    className="primary"
    disabled={!output || pending || offered}
    onClick={offer}
  >
              {words.saveFile}
            </button>
            <button disabled={pending} onClick={() => setCopy(true)}>
              {words.copyInstead}
            </button>
          </>}
        <button onClick={close}>{words.done}</button>
      </div>
    </section>;
}

// src/card-fields.js
function formText(value) {
  return (value ?? "").replace(/\r\n?/g, "\n");
}
function changedCardFields(inputs, prior = {}) {
  const fields2 = {};
  for (const key of Object.keys(words.fields)) {
    if (!inputs.has(key)) continue;
    const original = prior[key];
    if (Array.isArray(original)) {
      const next = [];
      for (const [index, value] of inputs.getAll(key).entries()) {
        if (index < original.length && value === formText(original[index]))
          next.push(original[index]);
        else if (value.trim()) next.push(value);
      }
      if (next.length !== original.length || next.some((value, index) => value !== original[index]))
        fields2[key] = next;
    } else {
      const value = inputs.get(key);
      if (!formText(original) && !value.trim()) continue;
      if (value !== formText(original)) fields2[key] = value;
    }
  }
  return fields2;
}

// src/style.css
var style_default = "* {\n  box-sizing: border-box;\n}\nbody {\n  margin: 0;\n  background: #faf9f4;\n  color: #233c36;\n  font:\n    16px/1.5 'Gill Sans',\n    'Trebuchet MS',\n    sans-serif;\n}\nmain {\n  max-width: 1392px;\n  margin: auto;\n  padding: clamp(16px, 3.5vw, 56px);\n}\nbutton,\ninput,\ntextarea {\n  font: inherit;\n  color: inherit;\n}\nbutton {\n  cursor: pointer;\n  background: transparent;\n  border: 1px solid #acb9ad;\n  border-radius: 5px;\n  padding: 7px 14px;\n}\nbutton:hover:not(:disabled),\nsummary:hover {\n  background: #e5ece1;\n}\nbutton:disabled {\n  cursor: default;\n  opacity: 0.64;\n}\nbutton:focus-visible,\ninput:focus-visible,\nsummary:focus-visible,\ntextarea:focus-visible {\n  outline: 3px solid #a85721;\n  outline-offset: 2px;\n}\n.primary {\n  background: #254d40;\n  color: white;\n  border-color: #254d40;\n}\n.primary:hover:not(:disabled) {\n  background: #35634f;\n}\nheader,\n.line,\n.actions,\n.tools {\n  display: flex;\n  align-items: center;\n  justify-content: space-between;\n  gap: 12px;\n}\n.actions,\n.tools {\n  flex-wrap: wrap;\n  justify-content: flex-start;\n}\nheader {\n  align-items: flex-start;\n  border-bottom: 3px double #95a79a;\n  padding-bottom: 20px;\n}\nh1,\nh2,\nh3,\nh4,\np {\n  margin: 0;\n}\nh1,\nh2,\nh3,\n.personName {\n  font-family: Georgia, serif;\n  font-weight: normal;\n  line-height: 1.12;\n}\nh1 {\n  font-size: clamp(44px, 5vw, 76px);\n  letter-spacing: -0.055em;\n}\nheader p {\n  max-width: 540px;\n  margin-top: 9px;\n}\nh2 {\n  font-size: clamp(32px, 4vw, 58px);\n  letter-spacing: -0.04em;\n}\nh3 {\n  font-size: 27px;\n  margin: 18px 0 12px;\n}\nh4 {\n  font-size: 17px;\n}\n.layout {\n  display: grid;\n  grid-template-columns: minmax(245px, 31%) minmax(0, 1fr);\n  min-height: 56vh;\n}\naside {\n  padding: 24px 22px 24px 0;\n  border-right: 1px solid #bbc9bd;\n}\narticle {\n  padding: 28px clamp(16px, 4vw, 64px);\n  max-width: 910px;\n  overflow-wrap: anywhere;\n}\n.line h3 {\n  margin: 0;\n}\n.search,\nlabel input,\nlabel textarea {\n  width: 100%;\n  display: block;\n  border: 1px solid #acb9ad;\n  border-radius: 5px;\n  background: #fffef9;\n  padding: 9px 11px;\n}\n.search {\n  margin: 16px 0;\n}\n.row {\n  display: flex;\n  align-items: center;\n  width: 100%;\n  text-align: left;\n  gap: 12px;\n  border: 0;\n  border-radius: 0;\n  border-bottom: 1px solid #d8ded4;\n  padding: 11px 6px;\n}\n.selected {\n  background: #e5ece1;\n}\n.own {\n  border-block: 1px solid #94a598;\n  margin-bottom: 10px;\n}\n.stamp {\n  width: 40px;\n  height: 40px;\n  border-radius: 50%;\n  background: #dce5d4;\n  color: #345440;\n  display: inline-grid;\n  place-items: center;\n  font:\n    19px Georgia,\n    serif;\n  flex: none;\n}\n.own .stamp,\n.hero .stamp {\n  background: #295044;\n  color: #fff9e6;\n}\n.hero {\n  padding: 18px 0 24px;\n  border-bottom: 1px solid #a4b7a8;\n}\n.hero .stamp {\n  width: 57px;\n  height: 57px;\n  font-size: 25px;\n  margin-bottom: 10px;\n}\n.hero h2 {\n  margin: 0 0 6px;\n}\n.personName {\n  font-size: 20px;\n}\n.muted,\nsmall,\ndt {\n  color: #52655e;\n}\nsmall {\n  display: block;\n  font-size: 13px;\n}\n.tabs {\n  display: flex;\n  gap: 6px;\n  flex-wrap: wrap;\n  padding: 12px 0;\n  border-bottom: 1px solid #cbd4c9;\n}\n.tabs button {\n  border: 0;\n}\n.tabs [aria-pressed='true'] {\n  background: #dee7d8;\n}\n.blank {\n  padding: 38px 0;\n}\n.blank p {\n  margin: 10px 0;\n}\n.entry {\n  border-left: 2px solid #b1bda7;\n  padding-left: 15px;\n  margin: 16px 0 22px;\n}\n.entry p,\n.entry small {\n  margin: 5px 0;\n  white-space: pre-wrap;\n}\ndl {\n  margin: 0;\n}\ndl > div {\n  display: grid;\n  grid-template-columns: minmax(90px, 28%) 1fr;\n  gap: 12px;\n  border-bottom: 1px solid #d8ded4;\n  padding: 8px 0;\n}\ndd {\n  margin: 0;\n  white-space: pre-wrap;\n}\nfooter {\n  border-top: 1px solid #acbaad;\n  padding-top: 15px;\n  color: #53665e;\n  font-size: 13px;\n}\nsummary {\n  cursor: pointer;\n}\nheader details {\n  position: relative;\n}\nheader details > div {\n  position: absolute;\n  right: 0;\n  background: #fffef9;\n  border: 1px solid #abb8a9;\n  border-radius: 6px;\n  padding: 14px;\n  width: 210px;\n  z-index: 2;\n}\nheader details button {\n  width: 100%;\n  margin-top: 5px;\n}\n.back {\n  display: none;\n}\nform {\n  max-width: 560px;\n}\nlabel {\n  display: block;\n  margin: 12px 0;\n}\ntextarea {\n  min-height: 70px;\n}\nlabel input,\nlabel textarea {\n  margin-top: 4px;\n}\n[role='alert'] {\n  background: #ffefd9;\n  padding: 12px;\n  margin: 10px 0;\n}\n.busy {\n  padding: 16px;\n}\n.tools {\n  margin-top: 12px;\n}\ndetails dd {\n  margin-left: 10px;\n}\nfooter details {\n  margin-top: 8px;\n}\n@media (max-width: 660px) {\n  main {\n    padding: 18px 16px;\n  }\n  header {\n    padding-bottom: 14px;\n  }\n  header p {\n    font-size: 14px;\n  }\n  .layout {\n    display: block;\n  }\n  .detail aside,\n  .list article {\n    display: none;\n  }\n  aside,\n  article {\n    padding: 18px 0;\n    border: 0;\n  }\n  .back {\n    display: inline-block;\n  }\n  .hero {\n    padding: 16px 0;\n  }\n  .entry {\n    margin: 12px 0;\n  }\n  .layout {\n    min-height: 48vh;\n  }\n}\n@media (max-width: 660px) {\n  .list .selected {\n    background: transparent;\n  }\n}\nheader summary {\n  white-space: nowrap;\n}\n.transfer {\n  max-width: 680px;\n  padding: 28px 0;\n  overflow-wrap: anywhere;\n}\n.transfer h2,\n.transfer p,\n.transfer dl {\n  margin-bottom: 16px;\n}\n.transfer .actions,\n.exportOne {\n  margin-top: 16px;\n}\n.transfer textarea {\n  font: 14px/1.4 monospace;\n}\n.choices {\n  max-height: 50vh;\n  overflow-y: auto;\n}\n.choice {\n  display: flex;\n  align-items: baseline;\n  gap: 12px;\n  padding: 10px 0;\n  margin: 0;\n  border-bottom: 1px solid #d8ded4;\n}\n.choice input {\n  width: auto;\n  accent-color: #254d40;\n}\n.previewCard {\n  border-bottom: 1px solid #d8ded4;\n}\n.previewCard .choice {\n  border: 0;\n}\n.matchChoice {\n  margin: 0 0 12px 26px;\n  padding: 0;\n  border: 0;\n}\n.matchChoice legend {\n  font-size: 14px;\n  color: #52655e;\n}\n.matchChoice label {\n  display: inline-flex;\n  gap: 8px;\n  align-items: center;\n  padding: 5px 12px 5px 0;\n  margin: 0;\n  cursor: pointer;\n}\n.matchChoice input {\n  width: auto;\n  margin: 0;\n  accent-color: #254d40;\n}\n";

// src/Contacts.jsx
var book = contacts(kv);
var me = appId + "/me/me";
function initials(name) {
  return name.trim().split(/\s+/).slice(0, 2).map((n) => Array.from(n)[0]).join("");
}
function Stamp({ name }) {
  return <span aria-hidden="true" className="stamp">
      {initials(name)}
    </span>;
}
function display(v) {
  if (Array.isArray(v)) return v.map(display).join("\n");
  if (v && typeof v === "object")
    return Object.entries(v).map(([k, x]) => k.replaceAll("_", " ") + " \xB7 " + display(x)).join("\n");
  return String(v ?? "");
}
function Details({ data }) {
  return Object.keys(data).length ? <dl>
      {Object.entries(data).map(([k, v]) => <div key={k}>
          <dt>
            {Object.hasOwn(words.fields, k) ? words.fields[k] : k.replaceAll("_", " ")}
          </dt>
          <dd>{display(v)}</dd>
        </div>)}
    </dl> : <p>{words.noDetails}</p>;
}
function Form({ card: card2, mode, note, onSave, cancel, busy }) {
  const entry = mode === "entry", d = card2?.value.data, prior = note?.value.data.private || {};
  function submit(e) {
    e.preventDefault();
    const inputs = new FormData(e.currentTarget);
    if (entry) {
      const fields2 = {};
      for (const [key, value] of inputs)
        if (value.trim()) fields2[key] = value.trim();
      if (note) fields2.replaces = note.key;
      onSave(null, fields2);
      return;
    }
    const name = inputs.get("name");
    onSave(
      name === formText(d?.name) ? d?.name : name,
      changedCardFields(inputs, d?.private)
    );
  }
  return <form onSubmit={submit}>
      <fieldset disabled={busy} style={{ border: 0, padding: 0, margin: 0 }}>
        <h3>
          {entry ? note ? words.correct : words.addEntry : card2 ? words.edit : words.add}
        </h3>
        {entry ? <>
            {["label", "text", "source", "learned"].map((k) => <label key={k}>
                {k === "label" ? words.topic : words[k]}
                {k === "text" ? <textarea
    required
    autoFocus
    name={k}
    defaultValue={prior[k]}
  /> : <input
    type={k === "learned" ? "date" : "text"}
    name={k}
    defaultValue={prior[k]}
  />}
              </label>)}
          </> : <>
            <label>
              {words.name}
              {/[\r\n]/.test(d?.name) ? <textarea
    name="name"
    required
    autoFocus
    defaultValue={d.name}
  /> : <input
    name="name"
    required
    pattern=".*\S.*"
    autoFocus
    defaultValue={d?.name}
  />}
            </label>
            {Object.keys(words.fields).filter(
    (k) => d?.private[k] == null || typeof d.private[k] === "string" || Array.isArray(d.private[k]) && d.private[k].every((x) => typeof x === "string")
  ).map((k) => {
    const value = d?.private[k];
    if (Array.isArray(value))
      return [...value, ""].map((item, index) => <label key={k + index}>
                      {words.fields[k]} {index + 1}
                      <textarea name={k} defaultValue={item} />
                    </label>);
    return <label key={k}>
                    {words.fields[k]}
                    {k === "blurb" || k === "addresses" || /[\r\n]/.test(value) ? <textarea name={k} defaultValue={value ?? ""} /> : <input name={k} defaultValue={value ?? ""} />}
                  </label>;
  })}
          </>}
        <div className="actions">
          <button className="primary">{entry ? words.saveEntry : words.save}</button>
          <button type="button" onClick={cancel}>
            {words.cancel}
          </button>
        </div>
      </fieldset>
    </form>;
}
function Entry({ row, correct }) {
  const { data, by } = row.value, p = data.private;
  return <section className="entry">
      <small>
        {p.learned || data.added} · {author(by)}
      </small>
      <h4>{p.label || words.untitled}</h4>
      <p>{p.text}</p>
      {p.source && <small>
          {words.from} {p.source}
        </small>}
      {correct && <button onClick={() => correct(row)}>{words.correct}</button>}
    </section>;
}
function mergeRows(current, changed) {
  const rows = new Map(current.map((row) => [row.key, row]));
  for (const row of changed) rows.set(row.key, row);
  return [...rows.values()];
}
function Contacts() {
  const [rows, setRows] = useState2([]), [busy, setBusy] = useState2(true), [error, setError] = useState2(""), [key, select] = useState2(null);
  const [query, search] = useState2(""), [tab, setTab] = useState2("profile"), [mode, setMode] = useState2(""), [note, setNote] = useState2(null);
  const [detail, setDetail] = useState2(false);
  const [transfer, setTransfer] = useState2(null);
  const lock = useRef2(false), heading = useRef2(null), searchBox = useRef2(null);
  async function run(action) {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError("");
    try {
      const next = action && await action();
      if (next) {
        open(next);
        if (mode === "entry") setTab("entries");
      }
      if (action) {
        const changed = book.changes();
        setRows((current2) => mergeRows(current2, changed));
      } else {
        const fresh = await book.load(tab === "history" ? key : null);
        setRows(fresh);
        if (!key && !window.matchMedia("(max-width:660px)").matches) {
          select(people(fresh)[0]?.key || null);
        }
      }
    } catch (e) {
      setError(errorText(e.code));
    } finally {
      setBusy(false);
      lock.current = false;
    }
  }
  useEffect(() => {
    run();
  }, []);
  function open(id) {
    select(id);
    setDetail(true);
    setMode("");
    setTab("profile");
    requestAnimationFrame(() => heading.current?.focus());
  }
  function back() {
    setDetail(false);
    setMode("");
    requestAnimationFrame(() => searchBox.current?.focus());
  }
  const list = people(rows, query), card2 = rows.find((r) => r.key === key), data = card2?.value.data;
  const related = card2 ? rows.filter((r) => r.value.data.person === parseKey(key).person) : [];
  const notes = related.filter((r) => parseKey(r.key).kind === "note");
  const current = currentNotes(notes).sort(
    (a, b) => (b.value.data.private.learned || b.value.data.added).localeCompare(
      a.value.data.private.learned || a.value.data.added
    ) || b.key.localeCompare(a.key, "en", { numeric: true })
  );
  const old = notes.filter((r) => !current.includes(r));
  const versions = related.filter((r) => parseKey(r.key).kind === "history").sort((a, b) => b.key.localeCompare(a.key, "en", { numeric: true }));
  function openTab(next) {
    if (next !== "history") {
      setTab(next);
      return;
    }
    run(async () => {
      const history = await book.history(key);
      setRows((current2) => mergeRows(current2, history));
      setTab(next);
    });
  }
  function editEntry(row) {
    setNote(row);
    setMode("entry");
  }
  function add() {
    open(null);
    setMode("card");
  }
  function rowButton(id, title, subtitle, own = false) {
    return <button
      key={id}
      disabled={busy}
      className={"row " + (own ? "own " : "") + (id === key ? "selected" : "")}
      onClick={() => open(id)}
    >
        <Stamp name={title} />
        <span>
          <span className="personName">{title}</span>
          <small>{subtitle}</small>
        </span>
      </button>;
  }
  return <main>
      <style>{style_default}</style>
      <header>
        <div>
          <h1>{words.title}</h1>
          <p>{words.purpose}</p>
        </div>
        {!transfer && <details>
            <summary>{words.menu}</summary>
            <div>
              <button
    disabled={busy || !!error}
    onClick={() => setTransfer("import")}
  >
                {words.import}
              </button>
              <button
    disabled={busy || !!error}
    onClick={() => setTransfer("all")}
  >
                {words.exportAll}
              </button>
            </div>
          </details>}
      </header>
      {error && <div role="alert">
          {error}{" "}
          <button
    onClick={() => {
      setMode("");
      run();
    }}
  >
            {words.retry}
          </button>
        </div>}
      {book.skipped() > 0 && <small role="status">
          {book.skipped()}{" "}
          {book.skipped() === 1 ? words.skippedEntry : words.skippedEntries}
        </small>}
      {busy && <p className="busy" role="status">
          {mode || tab === "history" ? words.saving : words.loading}
        </p>}
      {transfer === "import" ? <ImportCards
    rows={rows}
    book={book}
    close={(changed) => {
      setTransfer(null);
      if (changed) setRows(mergeRows(rows, book.changes()));
    }}
  /> : transfer ? <ExportCards
    cards={transfer === "one" ? [card2] : people(rows)}
    own={transfer === "all" && rows.find((r) => r.key === me)}
    single={transfer === "one"}
    close={() => setTransfer(null)}
  /> : <section
    className={"layout " + (detail ? "detail" : "list")}
    aria-busy={busy}
  >
          <aside>
            <div className="line">
              <h3>{words.people}</h3>
              <button
    disabled={busy || !!error}
    className="primary"
    onClick={add}
  >
                {words.add}
              </button>
            </div>
            <input
    className="search"
    type="search"
    ref={searchBox}
    aria-label={words.search}
    placeholder={words.search}
    value={query}
    onChange={(e) => search(e.target.value)}
  />
            {rowButton(
    me,
    words.me,
    rows.find((r) => r.key === me)?.value.data.name || words.own,
    true
  )}
            {list.map(
    (r) => rowButton(
      r.key,
      r.value.data.name,
      display(
        r.value.data.private.organization || r.value.data.private.role || ""
      )
    )
  )}
            {!busy && !error && !list.length && <p className="blank">{query ? words.noMatch : words.emptyText}</p>}
          </aside>
          <article>
            <button className="back" onClick={back}>
              {words.back}
            </button>
            {mode ? <Form
    key={key + mode}
    card={card2}
    mode={mode}
    busy={busy || !!error}
    note={note}
    cancel={() => {
      setMode("");
      if (!key) back();
    }}
    onSave={(name, fields2) => run(
      () => mode === "entry" ? book.append(key, fields2) : book.save({ key, expected: card2?.value, name, fields: fields2 })
    )}
  /> : data ? <>
                <div className="hero">
                  <div className="line">
                    <Stamp name={data.name} />
                    <button
    disabled={busy || !!error}
    onClick={() => setMode("card")}
  >
                      {words.edit}
                    </button>
                  </div>
                  <h2 ref={heading} tabIndex={-1}>
                    {data.name}
                  </h2>
                  <small>
                    {key === me ? words.own + " \xB7 " : ""}
                    {author(card2.value.by)} · {card2.value.at.slice(0, 10)}
                  </small>
                </div>
                <nav className="tabs">
                  {["profile", "entries", "history"].map((t) => <button
    key={t}
    aria-pressed={tab === t}
    disabled={busy}
    onClick={() => openTab(t)}
  >
                      {words[t]}
                    </button>)}
                </nav>
                {tab === "profile" && <>
                    <h3>{words.profile}</h3>
                    <Details data={data.private} />
                    {key !== me && <button
    className="exportOne"
    disabled={busy || !!error}
    onClick={() => setTransfer("one")}
  >
                        {words.exportOne}
                      </button>}
                  </>}
                {tab === "entries" && <>
                    <div className="line tools">
                      <h3>{words.entries}</h3>
                      <button
    disabled={busy || !!error}
    onClick={() => editEntry(null)}
  >
                        {words.addEntry}
                      </button>
                    </div>
                    {current.length ? current.map((r) => <Entry key={r.key} row={r} correct={editEntry} />) : <p>{words.emptyEntries}</p>}
                    {!!old.length && <details>
                        <summary>{words.earlier}</summary>
                        {old.map((r) => <Entry key={r.key} row={r} />)}
                      </details>}
                  </>}
                {tab === "history" && <>
                    <h3>{words.history}</h3>
                    {!versions.length && <p>{words.noHistory}</p>}
                    {versions.map((r) => {
    const prior = r.value.data.private.prior;
    return <section className="entry" key={r.key}>
                          <small>
                            {r.value.at} · {author(r.value.by)}
                          </small>
                          <h4>{words.actions[r.value.data.action]}</h4>
                          {prior && <>
                              <p>
                                {prior.data.name} · {author(prior.by)}
                              </p>
                              <Details data={prior.data.private} />
                              <button
      disabled={busy || !!error}
      onClick={() => run(
        () => book.save({
          key,
          expected: card2.value,
          saved: r
        })
      )}
    >
                                {words.restore}
                              </button>
                            </>}
                        </section>;
  })}
                  </>}
              </> : !busy && !error && <section className="blank">
                  <h2>
                    {key === me ? words.own : rows.some((r) => parseKey(r.key).kind === "person") ? words.choose : words.empty}
                  </h2>
                  <p>
                    {key === me ? words.emptyMe : key ? words.chooseText : words.emptyText}
                  </p>
                  <button
    className="primary"
    onClick={() => key === me ? setMode("card") : add()}
  >
                    {key === me ? words.createMe : words.add}
                  </button>
                </section>}
          </article>
        </section>}
      <footer>
        {words.privacy}
        <details>
          <summary>{words.about}</summary>
          <p>
            {words.location} <code>{appId}/</code>.
          </p>
        </details>
      </footer>
    </main>;
}
export {
  Contacts as default
};
