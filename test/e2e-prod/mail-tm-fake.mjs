// A stand-in for api.mail.tm for unit tests: importing it replaces fetch in this process (also as
// `node --import ./mail-tm-fake.mjs`, so a child process never reaches the network). One domain,
// accounts, tokens, messages and deletes; an unknown address or password gets 401, like mail.tm.
export const fake = { accounts: new Map(), messages: [], deleted: [], createStatus: 201, listStatus: 200, calls: [] };

globalThis.fetch = async (url, { method = "GET", body, headers = {} } = {}) => {
  const { pathname } = new URL(url);
  fake.calls.push(`${method} ${pathname}`);
  const json = (status, value) => new Response(value === undefined ? null : JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  const sent = body ? JSON.parse(body) : {};
  const token = headers.authorization?.replace("Bearer ", "");
  if (pathname === "/domains") return json(200, { "hydra:member": [{ domain: "mail.example", isActive: true }] });
  if (pathname === "/accounts" && method === "POST") {
    if (fake.accounts.has(sent.address)) return json(422, { violations: [] });
    fake.accounts.set(sent.address, { id: `id-${fake.accounts.size + 1}`, password: sent.password });
    return json(fake.createStatus, fake.createStatus === 201 ? { id: fake.accounts.get(sent.address).id } : undefined);
  }
  if (pathname === "/token") {
    const account = fake.accounts.get(sent.address);
    return account?.password === sent.password ? json(200, { token: `t-${account.id}` }) : json(401, {});
  }
  const account = [...fake.accounts.values()].find((entry) => `t-${entry.id}` === token);
  if (account === undefined) return json(401, {});
  if (pathname === "/me") return json(200, { id: account.id });
  if (pathname === "/messages") {
    if (fake.listStatus !== 200) return json(fake.listStatus, {});
    return json(200, { "hydra:member": fake.messages.map(({ id, subject, createdAt }) => ({ id, subject, createdAt })) });
  }
  if (pathname.startsWith("/messages/")) { const message = fake.messages.find((entry) => entry.id === pathname.slice(10)); return message ? json(200, message) : json(404, {}); }
  if (pathname.startsWith("/accounts/") && method === "DELETE") { fake.deleted.push(pathname.slice(10)); return json(204); }
  return json(404, {});
};
