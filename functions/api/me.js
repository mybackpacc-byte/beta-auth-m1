// functions/api/me.js
import { json, methodNotAllowed } from "../../src/auth/http.js";
import { requireAuthContext } from "../../src/auth/session.js";

export async function onRequest({ request, env }) {
  if (request.method !== "GET") return methodNotAllowed();

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  return json({
    ok: true,
    user: ctx.user,
    active_tenant_id: ctx.session.active_tenant_id
  });
}
