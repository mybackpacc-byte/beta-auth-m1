// functions/api/tenant/pending.js
// Admin-only: list pending join requests for the ACTIVE tenant.

import { json, methodNotAllowed } from "../../../src/auth/http.js";
import { requireAuthContext } from "../../../src/auth/session.js";

export async function onRequest({ request, env }) {
  if (request.method !== "GET") return methodNotAllowed();

  const ctx = await requireAuthContext(env, request);
  if (ctx instanceof Response) return ctx;

  const tenantId = ctx.session.active_tenant_id;
  if (!tenantId) return json({ ok: true, tenant_id: null, pending: [] });

  const me = await env.DB.prepare(
    `SELECT role, status
     FROM user_tenants
     WHERE user_id = ?1 AND tenant_id = ?2
     LIMIT 1`
  ).bind(ctx.user.id, tenantId).first();

  if (!me || me.status !== "active") return json({ ok: false, error: "NO_ACTIVE_MEMBERSHIP" }, 403);
  if (me.role !== "admin") return json({ ok: false, error: "ADMIN_ONLY" }, 403);

  const rows = await env.DB.prepare(
    `SELECT ut.user_id AS user_id, u.email AS email, ut.created_at AS requested_at
     FROM user_tenants ut
     JOIN users u ON u.id = ut.user_id
     WHERE ut.tenant_id = ?1 AND ut.status = 'pending'
     ORDER BY ut.created_at ASC`
  ).bind(tenantId).all();

  return json({ ok: true, tenant_id: tenantId, pending: rows.results || [] });
}
