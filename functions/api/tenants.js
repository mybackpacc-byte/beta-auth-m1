// functions/api/tenants.js
// Lists the user's tenants + the current active tenant (stored on the session).

import { json, methodNotAllowed } from "../../src/auth/http.js";
import { requireAuthContext } from "../../src/auth/session.js";

export async function onRequest({ request, env }) {
  if (request.method !== "GET") return methodNotAllowed();

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const rows = await env.DB.prepare(
    `SELECT
       ut.tenant_id AS tenant_id,
       t.name       AS name,
       ut.role      AS role,
       ut.status    AS status
     FROM user_tenants ut
     JOIN tenants t ON t.id = ut.tenant_id
     WHERE ut.user_id = ?1
     ORDER BY t.created_at DESC`
  ).bind(ctx.user.id).all();

  return json({
    ok: true,
    active_tenant_id: ctx.session.active_tenant_id,
    tenants: rows.results || []
  });
}
