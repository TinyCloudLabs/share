import { handleRequest, handleScheduled } from "./app";
import type { Env } from "./d1";

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env, Date.now());
  },
  scheduled(_controller: unknown, env: Env): Promise<void> {
    return handleScheduled(env, Date.now());
  },
};
